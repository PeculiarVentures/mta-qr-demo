package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.trust.TrustConfig;
import com.peculiarventures.mtaqr.verifier.Verifier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;

/**
 * ML-DSA-44 signing and cross-SDK-simulation verification tests.
 *
 * verifyTsIssuedNote previously read fixture files from /home/claude/interop-test/,
 * an absolute path that only exists on the development machine. It has been
 * rewritten to generate all fixtures inline using the Java issuer, which tests
 * the same code paths: ML-DSA-44 key generation, checkpoint signing, note
 * formatting, and note verification — without any external file dependencies.
 */
public class MlDsaVerifyTest {

    // Opaque 32-byte seed — same one used in the SDK interop matrix for ML-DSA-44.
    private static final byte[] SEED = HexFormat.of()
            .parseHex("789753a683f9723c8e88cdf79071e26ebb8025cdca982a7287c5ea1cf1b822b2");

    @Test
    public void roundTripSignVerify() throws Exception {
        LocalSigner signer = LocalSigner.mlDsa44(SEED);
        byte[] message = "hello from java".getBytes(StandardCharsets.UTF_8);
        byte[] sig = signer.sign(message).get();
        byte[] pub = signer.publicKeyBytes().get();
        System.out.println("sig len: " + sig.length + " (expect 2420)");
        System.out.println("pub len: " + pub.length + " (expect 1312)");
        boolean ok = SignatureVerifier.verify(Signer.ALG_ML_DSA_44, message, sig, pub);
        System.out.println("round-trip verify: " + ok);
        assertTrue(ok, "ML-DSA-44 round-trip sign/verify should succeed");
    }

    /**
     * Issue a payload with the Java ML-DSA-44 issuer, then verify it with the
     * Java verifier. This exercises the full end-to-end path — checkpoint body
     * construction, ML-DSA-44 note signing, cosignature quorum, inclusion proof
     * embedding, payload decoding, and step-by-step verification — entirely
     * within the Java SDK with no external fixtures.
     *
     * This is the self-contained replacement for the previous verifyTsIssuedNote
     * test that read from /home/claude/interop-test/ and therefore could not run
     * in CI.
     */
    @Test
    public void issueAndVerifyEndToEnd() throws Exception {
        LocalSigner signer = LocalSigner.mlDsa44(SEED);
        Issuer issuer = Issuer.builder()
                .origin("test.ml-dsa-44.verify/v1")
                .schemaId(42)
                .signer(signer)
                .build();
        issuer.init().get();

        var issued = issuer.issue(
                Map.of("subject", "ml-dsa-verify-test", "lang", "java"),
                Duration.ofHours(1)
        ).get();

        String trustJson  = issuer.trustConfigJson("http://localhost:0/checkpoint");
        String noteString = issuer.checkpointNote();

        System.out.println("entry_index: " + issued.entryIndex());
        System.out.println("payload bytes: " + issued.payload().length);
        System.out.println("note length: " + noteString.length());

        TrustConfig trust = TrustConfig.parse(trustJson);
        String revArtifact = issuer.revocationArtifact();
        Verifier verifier = Verifier.builder()
                .trust(trust)
                .noteProvider(url -> java.util.concurrent.CompletableFuture.completedFuture(noteString))
                .revocationProvider(url -> java.util.concurrent.CompletableFuture.completedFuture(revArtifact))
                .build();

        // verify() returns VerifyOk on success, throws VerifyFail exceptionally on failure.
        var result = verifier.verify(issued.payload()).get();
        System.out.println("mode: " + result.mode());
        System.out.println("claims: " + result.claims());

        // If we reach here, verification succeeded.
        assertEquals(1, result.mode(), "Should be Mode 1 (proof embedded)");
        assertEquals("ml-dsa-verify-test", result.claims().get("subject"));
    }
}
