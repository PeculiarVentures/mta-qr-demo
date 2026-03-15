package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

public class MlDsaVerifyTest {

    @Test
    public void roundTripSignVerify() throws Exception {
        byte[] seed = MessageDigest.getInstance("SHA-256").digest("interop-ml-dsa-44".getBytes());
        LocalSigner signer = LocalSigner.mlDsa44(seed);
        byte[] message = "hello from java".getBytes(StandardCharsets.UTF_8);
        byte[] sig = signer.sign(message).get();
        byte[] pub = signer.publicKeyBytes().get();
        System.out.println("sig len: " + sig.length);
        System.out.println("pub len: " + pub.length);
        boolean ok = SignatureVerifier.verify(Signer.ALG_ML_DSA_44, message, sig, pub);
        System.out.println("round-trip verify: " + ok);
        assertTrue(ok);
    }

    @Test
    public void verifyTsIssuedNote() throws Exception {
        String note      = Files.readString(Path.of("/home/claude/interop-test/trust/ts-ml-dsa-44.note"));
        String trustJson = Files.readString(Path.of("/home/claude/interop-test/trust/ts-ml-dsa-44.json"));
        var trust = new ObjectMapper().readTree(trustJson);
        byte[] pubKey = HexFormat.of().parseHex(trust.get("issuer_pub_key_hex").asText());

        int blankIdx = note.indexOf("\n\n");
        byte[] body  = (note.substring(0, blankIdx) + "\n").getBytes(StandardCharsets.UTF_8);

        String issuerKeyName = trust.get("issuer_key_name").asText();
        String sigB64 = null;
        for (String line : note.substring(blankIdx + 2).split("\n")) {
            if (!line.isBlank() && line.contains(issuerKeyName)) {
                sigB64 = line.substring(line.lastIndexOf(' ') + 1).trim();
                break;
            }
        }
        assertNotNull(sigB64, "issuer sig line not found");
        byte[] sig = Base64.getDecoder().decode(sigB64);

        System.out.println("body len: " + body.length);
        System.out.println("sig len:  " + sig.length + " (expect 2420)");
        System.out.println("pub len:  " + pubKey.length + " (expect 1312)");

        boolean ok = SignatureVerifier.verify(Signer.ALG_ML_DSA_44, body, sig, pubKey);
        System.out.println("ts note ML-DSA verify in Java: " + ok);
        assertTrue(ok, "TS-issued ML-DSA-44 checkpoint note should verify in Java");
    }
}
