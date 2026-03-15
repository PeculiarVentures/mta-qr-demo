/**
 * Core signer abstraction for MTA-QR.
 *
 * The SDK never holds private key material. All signing operations go through
 * this interface, allowing GoodKey, local keys, or any compliant backend to
 * be used interchangeably.
 *
 * Implementations must be safe to call concurrently.
 */

export const SIG_ALG_ML_DSA_44  = 1 as const;
export const SIG_ALG_ECDSA_P256 = 4 as const;
export const SIG_ALG_ED25519    = 6 as const;

export type SigAlg =
  | typeof SIG_ALG_ML_DSA_44
  | typeof SIG_ALG_ECDSA_P256
  | typeof SIG_ALG_ED25519;

export function sigAlgName(alg: SigAlg): string {
  switch (alg) {
    case SIG_ALG_ED25519:    return "Ed25519";
    case SIG_ALG_ECDSA_P256: return "ECDSA-P256";
    case SIG_ALG_ML_DSA_44:  return "ML-DSA-44";
  }
}

export function sigAlgSigLen(alg: SigAlg): number {
  switch (alg) {
    case SIG_ALG_ED25519:    return 64;
    case SIG_ALG_ECDSA_P256: return 64;
    case SIG_ALG_ML_DSA_44:  return 2420;
  }
}

export function sigAlgPubKeyLen(alg: SigAlg): number {
  switch (alg) {
    case SIG_ALG_ED25519:    return 32;
    case SIG_ALG_ECDSA_P256: return 65;  // uncompressed 0x04 || X || Y
    case SIG_ALG_ML_DSA_44:  return 1312;
  }
}

/**
 * Signer is the only interface the Issuer needs from a key backend.
 *
 * - `sigAlg` and `keyName` are synchronous because they describe the key's
 *   identity, not its material, and must be available before any signing.
 * - `sign` and `publicKeyBytes` are async because they may involve a network
 *   call to GoodKey or an HSM.
 */
export interface Signer {
  /** Wire algorithm identifier. Determines signature and public key sizes. */
  readonly sigAlg: SigAlg;
  /**
   * Bare key name as it appears in tlog-checkpoint note signature lines.
   * Per c2sp.org/signed-note: just the human name (e.g. "example.com/log").
   * The full verifier key string (name+hex_keyid+base64(type+pub)) is in
   * the trust config only, not in the signature line itself.
   */
  readonly keyName: string;
  /**
   * Sign a raw message. The signer is responsible for any internal hashing
   * required by the algorithm (e.g. SHA-256 for ECDSA P-256). The SDK
   * always passes the full message, never a pre-computed hash.
   */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /** Raw public key bytes in the wire encoding for the algorithm. */
  publicKeyBytes(): Promise<Uint8Array>;
}

/**
 * LocalSigner is a synchronous specialization of Signer for in-process key
 * material. LocalSigners never perform I/O so sign() and publicKeyBytes()
 * return plain values rather than Promises. The async Signer interface is
 * satisfied because a T is assignable to Promise<T> in TypeScript when the
 * value is used in an await expression — but call sites that know they hold
 * a LocalSigner can call these synchronously without await.
 *
 * Use this interface when you need the signers locally in the HTTP services.
 * GoodKey and other network signers implement the base Signer interface.
 */
export interface LocalSigner {
  readonly sigAlg:   SigAlg;
  readonly keyName:  string;
  sign(message: Uint8Array): Uint8Array;
  publicKeyBytes(): Uint8Array;
}
