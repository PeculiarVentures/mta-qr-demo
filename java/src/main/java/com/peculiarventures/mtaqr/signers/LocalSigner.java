package com.peculiarventures.mtaqr.signers;

import com.peculiarventures.mtaqr.signing.Signer;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

/**
 * LocalSigner holds raw key material in process memory.
 *
 * <p><b>FOR TESTING ONLY.</b> Use {@link GoodKeySigner} for production.
 *
 * <p>ML-DSA-44 uses BouncyCastle 1.79+ {@code pqc.crypto.mldsa} (FIPS 204).
 * This produces keys identical to Go (cloudflare/circl), TypeScript
 * (@noble/post-quantum), and Rust (ml-dsa crate) from the same 32-byte seed.
 */
public final class LocalSigner implements Signer {

    private final int          alg;
    private final String       keyName;
    private final byte[]       pubKey;
    private final SignFunction  signFn;

    @FunctionalInterface
    private interface SignFunction {
        byte[] sign(byte[] message) throws Exception;
    }

    private LocalSigner(int alg, String keyName, byte[] pubKey, SignFunction signFn) {
        this.alg     = alg;
        this.keyName = keyName;
        this.pubKey  = pubKey.clone();
        this.signFn  = signFn;
    }

    @Override public int    getAlg()     { return alg; }
    @Override public String getKeyName() { return keyName; }

    @Override
    public CompletableFuture<byte[]> sign(byte[] message) {
        return CompletableFuture.supplyAsync(() -> {
            try { return signFn.sign(message); }
            catch (Exception e) { throw new RuntimeException("LocalSigner: sign failed", e); }
        });
    }

    @Override
    public CompletableFuture<byte[]> publicKeyBytes() {
        return CompletableFuture.completedFuture(pubKey.clone());
    }

    // --- factory methods ---

    private static String buildKeyName(String label, byte[] pubBytes) {
        // Per c2sp.org/signed-note: key name in signature lines is the bare label.
        // The key hash and public key go in the trust config only.
        return label;
    }

    /** Creates a LocalSigner from a 32-byte Ed25519 seed. */
    public static LocalSigner ed25519(byte[] seed) {
        if (seed.length != 32) throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
        byte[] pubBytes = priv.generatePublicKey().getEncoded();
        return new LocalSigner(
            ALG_ED25519,
            buildKeyName("local-Ed25519", pubBytes),
            pubBytes,
            msg -> {
                Ed25519Signer signer = new Ed25519Signer();
                signer.init(true, priv);
                signer.update(msg, 0, msg.length);
                return signer.generateSignature();
            }
        );
    }

    /** Creates a LocalSigner from a 32-byte ECDSA P-256 scalar. */
    public static LocalSigner ecdsaP256(byte[] scalar) {
        if (scalar.length != 32) throw new IllegalArgumentException("P-256 scalar must be 32 bytes");
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters domain = new ECDomainParameters(
            curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(
            new BigInteger(1, scalar), domain);
        byte[] pubBytes = domain.getG().multiply(priv.getD()).getEncoded(false);
        return new LocalSigner(
            ALG_ECDSA_P256,
            buildKeyName("local-ECDSA-P256", pubBytes),
            pubBytes,
            msg -> {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] digest = sha.digest(msg);
                ECDSASigner signer = new ECDSASigner();
                signer.init(true, priv);
                BigInteger[] rs = signer.generateSignature(digest);
                byte[] out = new byte[64];
                byte[] rb = toFixed32(rs[0]);
                byte[] sb = toFixed32(rs[1]);
                System.arraycopy(rb, 0, out, 0,  32);
                System.arraycopy(sb, 0, out, 32, 32);
                return out;
            }
        );
    }

    /**
     * Creates a LocalSigner from a 32-byte ML-DSA-44 seed (ξ).
     *
     * <p>Uses BouncyCastle 1.79+ {@code MLDSAKeyPairGenerator} which implements
     * the FIPS 204 {@code ML-DSA.KeyGen_internal(ξ)} algorithm. This produces
     * identical key pairs to Go (cloudflare/circl), TypeScript (@noble/post-quantum),
     * and Rust (ml-dsa crate) from the same seed.
     */
    public static LocalSigner mlDsa44(byte[] seed) throws Exception {
        if (seed.length != 32) throw new IllegalArgumentException("ML-DSA-44 seed must be 32 bytes");

        // Pass seed as xi directly to the FIPS 204 keygen — one 32-byte RNG call.
        // BC 1.79+ MLDSAKeyPairGenerator requests exactly 32 bytes from SecureRandom
        // and treats them as xi per FIPS 204 §5.1.
        SecureRandom xi = new SecureRandom() {
            boolean consumed = false;
            @Override public void nextBytes(byte[] bytes) {
                if (consumed) throw new IllegalStateException("MLDSAKeyPairGenerator made unexpected second RNG call");
                if (bytes.length != 32) throw new IllegalStateException("Expected 32-byte xi, got " + bytes.length);
                System.arraycopy(seed, 0, bytes, 0, 32);
                consumed = true;
            }
        };

        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(xi, MLDSAParameters.ml_dsa_44));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();
        MLDSAPublicKeyParameters  pub  = (MLDSAPublicKeyParameters)  kp.getPublic();
        byte[] pubBytes = pub.getEncoded();

        return new LocalSigner(
            ALG_ML_DSA_44,
            buildKeyName("local-ML-DSA-44", pubBytes),
            pubBytes,
            msg -> {
                MLDSASigner signer = new MLDSASigner();
                signer.init(true, priv);
                signer.update(msg, 0, msg.length);
                return signer.generateSignature();
            }
        );
    }

    private static byte[] toFixed32(BigInteger n) {
        byte[] raw = n.toByteArray();
        if (raw.length == 32) return raw;
        if (raw.length == 33 && raw[0] == 0) return Arrays.copyOfRange(raw, 1, 33);
        byte[] out = new byte[32];
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }
}
