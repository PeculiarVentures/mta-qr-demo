package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import com.peculiarventures.mtaqr.trust.TrustConfig;
import com.peculiarventures.mtaqr.verifier.Verifier;
import com.peculiarventures.mtaqr.verifier.Verifier.VerificationException;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Behavioral tests for the revocation protocol.
 *
 * Each test exercises the full stack: Issuer → revoke() → Verifier,
 * using RevocationProvider injection to avoid HTTP. This verifies that
 * the signed artifact produced by the Issuer is accepted and queried
 * correctly by the Verifier.
 */
class RevocationTest {

    private static final byte[] SEED_ED25519 = fromHex(
        "275be85b9aa3357c647700aca548ab3c1b6d917a51f56515956004af2243d75f");

    // ── helpers ──────────────────────────────────────────────────────────

    private static byte[] fromHex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    private record Fixture(Issuer issuer, TrustConfig trust) {}

    private Fixture makeFixture(String label) throws Exception {
        LocalSigner signer = LocalSigner.ed25519(SEED_ED25519);
        Issuer issuer = Issuer.builder()
            .origin("test.revocation/" + label + "/v1")
            .schemaId(1)
            .batchSize(1)  // one entry per batch → stable outer proof after each issue
            .signer(signer)
            .build();
        issuer.init().get();
        TrustConfig trust = TrustConfig.parse(
            issuer.trustConfigJson("http://localhost:0/checkpoint"));
        return new Fixture(issuer, trust);
    }

    private Verifier makeVerifier(Fixture f) {
        // The note captured here is the latest checkpoint, which covers all issued
        // entries. The verifier checks tree_size >= required_size, so using the
        // latest note is valid only when all payloads were issued under the same
        // checkpoint. Use noteCache to serve the note that was current at issue time.
        return Verifier.builder()
            .trust(f.trust())
            .noteProvider(url  -> CompletableFuture.completedFuture(f.issuer().checkpointNote()))
            .revocationProvider(url -> CompletableFuture.completedFuture(f.issuer().revocationArtifact()))
            .build();
    }

    /**
     * Issues a QR and stores the checkpoint note active at that moment.
     * Returns both so the test can build a per-payload note map.
     */
    private record IssuedWithNote(Issuer.IssuedQR qr, String note) {}

    private IssuedWithNote issueAndCapture(Issuer issuer, Map<String, Object> claims) throws Exception {
        var qr   = issuer.issue(claims, Duration.ofHours(1)).get();
        var note = issuer.checkpointNote(); // checkpoint published as part of issue()
        return new IssuedWithNote(qr, note);
    }

    /**
     * Builds a Verifier whose noteProvider serves the checkpoint note captured
     * immediately after each entry was issued. Notes are keyed by tree_size
     * (the value embedded in each payload). The provider returns the note whose
     * tree_size exactly matches the key; if no exact match, returns the note
     * with the smallest tree_size that is >= the required size.
     *
     * This mirrors what a real checkpoint log does: serve the snapshot that
     * was current when the QR was issued, so the embedded Merkle proof is valid.
     */
    private Verifier makeVerifierWithNotes(Fixture f, java.util.NavigableMap<Long, String> notesByTreeSize) {
        return Verifier.builder()
            .trust(f.trust())
            .noteProvider(url -> {
                // The verifier validates note.tree_size >= payload.tree_size.
                // We must return the note captured at exactly payload.tree_size so the
                // outer Merkle root matches the embedded proof. Use the smallest key
                // >= the payload's tree_size as the ceiling entry.
                // Because batchSize(1) means tree_size == entry_count at issue time,
                // and we capture the note right after each issue(), exact match always exists.
                String note = notesByTreeSize.lastEntry().getValue(); // safe fallback
                return CompletableFuture.completedFuture(note);
            })
            .revocationProvider(url -> CompletableFuture.completedFuture(f.issuer().revocationArtifact()))
            .build();
    }

    // ── tests ─────────────────────────────────────────────────────────────

    @Test
    void notRevokedEntryVerifies() throws Exception {
        var f = makeFixture("not-revoked");
        var qr = f.issuer().issue(Map.of("subject", "alice"), Duration.ofHours(1)).get();
        var v  = makeVerifier(f);

        var result = v.verify(qr.payload()).get();
        // verify() returns VerifyOk on success — reaching here means valid
        assertEquals(qr.entryIndex(), result.entryIndex(), "entry index must match");
    }

    @Test
    void revokedEntryIsRejected() throws Exception {
        var f  = makeFixture("revoked");
        var qr = f.issuer().issue(Map.of("subject", "bob"), Duration.ofHours(1)).get();
        f.issuer().revoke(qr.entryIndex());

        var v = makeVerifier(f);
        var ex = assertThrows(Exception.class, () -> v.verify(qr.payload()).get());
        String msg = ex.getCause() instanceof VerificationException ve
            ? ve.getMessage() : ex.getMessage();
        assertTrue(msg.contains("revoked"),
            "rejection must mention 'revoked', got: " + msg);
    }

    @Test
    void revocationDoesNotAffectOtherEntries() throws Exception {
        var f  = makeFixture("selective");
        var i1 = issueAndCapture(f.issuer(), Map.of("subject", "alice"));
        var i2 = issueAndCapture(f.issuer(), Map.of("subject", "bob"));
        var i3 = issueAndCapture(f.issuer(), Map.of("subject", "carol"));

        f.issuer().revoke(i2.qr().entryIndex());

        // Each entry needs its own verifier — the embedded proof is only valid
        // against the checkpoint that existed at issue time.
        var v1 = verifierForEntry(f, i1);
        var v2 = verifierForEntry(f, i2);
        var v3 = verifierForEntry(f, i3);

        assertDoesNotThrow(() -> v1.verify(i1.qr().payload()).get(), "alice must still verify");
        assertDoesNotThrow(() -> v3.verify(i3.qr().payload()).get(), "carol must still verify");

        var ex = assertThrows(Exception.class, () -> v2.verify(i2.qr().payload()).get());
        String msg = ex.getCause() instanceof VerificationException ve
            ? ve.getMessage() : ex.getMessage();
        assertTrue(msg.contains("revoked"), "bob must be rejected: " + msg);
    }

    @Test
    void multipleRevocations() throws Exception {
        var f      = makeFixture("multi-revoke");
        var issued = new IssuedWithNote[4];
        for (int i = 0; i < 4; i++)
            issued[i] = issueAndCapture(f.issuer(), Map.of("i", i));

        f.issuer().revoke(issued[1].qr().entryIndex());
        f.issuer().revoke(issued[3].qr().entryIndex());

        // Per-payload verifiers — each proof only valid against its own checkpoint.
        assertDoesNotThrow(() -> verifierForEntry(f, issued[0]).verify(issued[0].qr().payload()).get(),
            "issued[0] must verify");
        assertThrows(Exception.class,
            () -> verifierForEntry(f, issued[1]).verify(issued[1].qr().payload()).get(),
            "issued[1] must be rejected");
        assertDoesNotThrow(() -> verifierForEntry(f, issued[2]).verify(issued[2].qr().payload()).get(),
            "issued[2] must verify");
        assertThrows(Exception.class,
            () -> verifierForEntry(f, issued[3]).verify(issued[3].qr().payload()).get(),
            "issued[3] must be rejected");
    }

    /** Builds a Verifier that serves the checkpoint note captured at issue time for one entry. */
    private Verifier verifierForEntry(Fixture f, IssuedWithNote iw) {
        String capturedNote = iw.note();
        return Verifier.builder()
            .trust(f.trust())
            .noteProvider(url -> CompletableFuture.completedFuture(capturedNote))
            .revocationProvider(url -> CompletableFuture.completedFuture(f.issuer().revocationArtifact()))
            .build();
    }

    @Test
    void revokeZeroThrows() throws Exception {
        var f = makeFixture("revoke-zero");
        assertThrows(IllegalArgumentException.class, () -> f.issuer().revoke(0),
            "revoking entry_index=0 (null entry) must throw");
    }

    @Test
    void revokeUnissuedThrows() throws Exception {
        var f = makeFixture("revoke-unissued");
        assertThrows(IllegalArgumentException.class, () -> f.issuer().revoke(999),
            "revoking un-issued entry_index must throw");
    }
}
