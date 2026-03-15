package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.signing.SignatureVerifier;
import com.peculiarventures.mtaqr.signing.Signer;
import com.peculiarventures.mtaqr.signers.LocalSigner;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

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
}
