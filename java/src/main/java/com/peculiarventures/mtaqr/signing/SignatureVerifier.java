package com.peculiarventures.mtaqr.signing;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Signature verification for MTA-QR. Always dispatches by algorithm identifier.
 */
public final class SignatureVerifier {

    private SignatureVerifier() {}

    public static boolean verify(int alg, byte[] message, byte[] sig, byte[] pubKey) {
        return switch (alg) {
            case Signer.ALG_ED25519    -> verifyEd25519(message, sig, pubKey);
            case Signer.ALG_ECDSA_P256 -> verifyEcdsaP256(message, sig, pubKey);
            case Signer.ALG_ML_DSA_44  -> verifyMlDsa44(message, sig, pubKey);
            default                    -> false;
        };
    }

    private static boolean verifyEd25519(byte[] message, byte[] sig, byte[] pubKey) {
        if (pubKey.length != 32 || sig.length != 64) return false;
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            byte[] spki = concat(hexToBytes("302a300506032b6570032100"), pubKey);
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(spki));
            Signature sv = Signature.getInstance("Ed25519");
            sv.initVerify(pk);
            sv.update(message);
            return sv.verify(sig);
        } catch (Exception e) { return false; }
    }

    private static boolean verifyEcdsaP256(byte[] message, byte[] sig, byte[] pubKey) {
        if (sig.length != 64 || pubKey.length != 65 || pubKey[0] != 0x04) return false;
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            byte[] spki = concat(hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200"), pubKey);
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(spki));
            Signature sv = Signature.getInstance("SHA256withECDSA");
            sv.initVerify(pk);
            sv.update(message);
            return sv.verify(rawToDer(sig));
        } catch (Exception e) { return false; }
    }

    private static boolean verifyMlDsa44(byte[] message, byte[] sig, byte[] pubKey) {
        // FIPS 204 ML-DSA-44: public key 1312 bytes, signature 2420 bytes
        if (sig.length != 2420 || pubKey.length != 1312) return false;
        try {
            MLDSAPublicKeyParameters pk =
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, pubKey);
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, pk);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(sig);
        } catch (Exception e) { return false; }
    }

    static byte[] rawToDer(byte[] raw) {
        byte[] r = stripLeadingZeros(Arrays.copyOfRange(raw, 0, 32));
        byte[] s = stripLeadingZeros(Arrays.copyOfRange(raw, 32, 64));
        if ((r[0] & 0x80) != 0) r = concat(new byte[]{0x00}, r);
        if ((s[0] & 0x80) != 0) s = concat(new byte[]{0x00}, s);
        byte[] inner = concat(
            new byte[]{0x02, (byte) r.length}, r,
            new byte[]{0x02, (byte) s.length}, s
        );
        return concat(new byte[]{0x30, (byte) inner.length}, inner);
    }

    private static byte[] stripLeadingZeros(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return Arrays.copyOfRange(b, i, b.length);
    }

    static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                               + Character.digit(hex.charAt(i + 1), 16));
        return out;
    }
}
