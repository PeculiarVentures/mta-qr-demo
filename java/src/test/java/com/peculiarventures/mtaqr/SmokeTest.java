package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.issuer.Issuer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import com.peculiarventures.mtaqr.trust.TrustConfig;
import com.peculiarventures.mtaqr.verifier.Verifier;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MTA-QR SDK — smoke tests.
 *
 * Test seeds are arbitrary fixed bytes generated from /dev/urandom.
 * They are not derived from strings or passphrases and carry no semantic meaning.
 * Do not use these in production — use GoodKeySigner with hardware-backed keys.
 */
public class SmokeTest {

    // Arbitrary fixed test seeds — not derived from any string or passphrase.
    private static final byte[] SEED_ED25519    = fromHex("275be85b9aa3357c647700aca548ab3c1b6d917a51f56515956004af2243d75f");
    private static final byte[] SEED_ECDSA_P256 = fromHex("4b1477c4270aeb87ed40f222db87c132bf62092ed1ffc153b99729c2fb3c0820");
    private static final byte[] SEED_ML_DSA_44  = fromHex("789753a683f9723c8e88cdf79071e26ebb8025cdca982a7287c5ea1cf1b822b2");

    private static byte[] fromHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    private void roundTrip(String label, LocalSigner signer) throws Exception {
        String origin = "test.mta-qr.example/" + label + "/v1";
        Issuer issuer = Issuer.builder().origin(origin).schemaId(1).signer(signer).build();
        issuer.init().get();

        var qr = issuer.issue(Map.of("subject", "test"), Duration.ofHours(1)).get();
        TrustConfig trust = TrustConfig.parse(issuer.trustConfigJson("http://localhost:0/checkpoint"));
        String note = issuer.checkpointNote();
        String revArtifact = issuer.revocationArtifact();
        Verifier v = Verifier.builder()
            .noteProvider(url -> CompletableFuture.completedFuture(note))
            .revocationProvider(url -> CompletableFuture.completedFuture(revArtifact))
            .build().addAnchor(trust);

        var result = v.verify(qr.payload()).get();
        assertEquals(qr.entryIndex(), result.entryIndex(), label + ": entry index mismatch");
        assertEquals("test", String.valueOf(result.claims().get("subject")), label + ": claims mismatch");
    }

    private void rejectTampered(String label, LocalSigner signer) throws Exception {
        String origin = "test.mta-qr.example/" + label + "-tamper/v1";
        Issuer issuer = Issuer.builder().origin(origin).schemaId(1).signer(signer).build();
        issuer.init().get();

        var qr = issuer.issue(Map.of("subject", "legit"), Duration.ofHours(1)).get();
        byte[] tampered = qr.payload().clone();
        tampered[tampered.length - 10] ^= (byte) 0xff;

        TrustConfig trust = TrustConfig.parse(issuer.trustConfigJson("http://localhost:0/checkpoint"));
        String note = issuer.checkpointNote();
        String revArtifact = issuer.revocationArtifact();
        Verifier v = Verifier.builder()
            .noteProvider(url -> CompletableFuture.completedFuture(note))
            .revocationProvider(url -> CompletableFuture.completedFuture(revArtifact))
            .build().addAnchor(trust);

        assertThrows(Exception.class, () -> v.verify(tampered).get(), label + ": tampered payload should fail");
    }

    @Test public void ed25519IssueAndVerify()    throws Exception { roundTrip("ed25519",    LocalSigner.ed25519(SEED_ED25519)); }
    @Test public void ed25519RejectTampered()    throws Exception { rejectTampered("ed25519", LocalSigner.ed25519(SEED_ED25519)); }
    @Test public void ecdsaP256IssueAndVerify()  throws Exception { roundTrip("ecdsa-p256",  LocalSigner.ecdsaP256(SEED_ECDSA_P256)); }
    @Test public void ecdsaP256RejectTampered()  throws Exception { rejectTampered("ecdsa-p256", LocalSigner.ecdsaP256(SEED_ECDSA_P256)); }
    @Test public void mlDsa44IssueAndVerify()    throws Exception { roundTrip("ml-dsa-44",   LocalSigner.mlDsa44(SEED_ML_DSA_44)); }
    @Test public void mlDsa44RejectTampered()    throws Exception { rejectTampered("ml-dsa-44", LocalSigner.mlDsa44(SEED_ML_DSA_44)); }
}
