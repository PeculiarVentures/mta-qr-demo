package com.peculiarventures.mtaqr.signing;

import java.util.concurrent.CompletableFuture;

/**
 * Core signing abstraction for MTA-QR.
 *
 * <p>The SDK never holds private key material. All signing operations go through
 * this interface, allowing GoodKey, local keys, or any compliant backend to be
 * used interchangeably.
 *
 * <p>Implementations must be safe for concurrent use.
 */
public interface Signer {

    /** Wire algorithm identifier for ML-DSA-44 (FIPS 204). */
    int ALG_ML_DSA_44   = 1;
    /** Wire algorithm identifier for ECDSA P-256 / SHA-256, raw r||s wire format. */
    int ALG_ECDSA_P256  = 4;
    /** Wire algorithm identifier for Ed25519. */
    int ALG_ED25519     = 6;

    /**
     * Returns the wire algorithm identifier. Synchronous — must not block.
     */
    int getAlg();

    /**
     * Returns the key name as it appears in tlog-checkpoint note signature lines.
     * Format: {@code "<label>+<base64(pubkey)>"}. Synchronous — must not block.
     */
    String getKeyName();

    /**
     * Signs a raw message and returns the raw signature bytes.
     *
     * <p>The signer handles any internal hashing required by the algorithm.
     * The SDK always passes the full message, never a pre-computed hash.
     *
     * @param message the message to sign
     * @return a future that resolves to the raw signature bytes
     */
    CompletableFuture<byte[]> sign(byte[] message);

    /**
     * Returns the raw public key bytes in the wire encoding for the algorithm.
     *
     * @return a future that resolves to the raw public key bytes
     */
    CompletableFuture<byte[]> publicKeyBytes();

    // --- static helpers ---

    static String algName(int alg) {
        return switch (alg) {
            case ALG_ED25519    -> "Ed25519";
            case ALG_ECDSA_P256 -> "ECDSA-P256";
            case ALG_ML_DSA_44  -> "ML-DSA-44";
            default             -> String.format("unknown(0x%02x)", alg);
        };
    }

    static int sigLen(int alg) {
        return switch (alg) {
            case ALG_ED25519    -> 64;
            case ALG_ECDSA_P256 -> 64;  // raw r||s
            case ALG_ML_DSA_44  -> 2420;
            default             -> 0;
        };
    }

    static int pubKeyLen(int alg) {
        return switch (alg) {
            case ALG_ED25519    -> 32;
            case ALG_ECDSA_P256 -> 65;   // uncompressed 0x04 || X || Y
            case ALG_ML_DSA_44  -> 1312;
            default             -> 0;
        };
    }
}
