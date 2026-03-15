/**
 * Signing abstraction for MTA-QR — Ed25519, ECDSA P-256, and ML-DSA-44 (FIPS 204).
 *
 * Wire format: fixed-width raw encoding for all algorithms.
 *   Ed25519:     64 bytes
 *   ECDSA P-256: 64 bytes r||s (IEEE P1363 / WebCrypto "raw" format)
 *   ML-DSA-44:   2420 bytes (FIPS 204 §3)
 *
 * Public key encoding:
 *   Ed25519:     32 bytes (raw public key)
 *   ECDSA P-256: 65 bytes uncompressed (0x04 || X || Y)
 *   ML-DSA-44:   1312 bytes (FIPS 204 §5.2)
 *
 * Ed25519 and ECDSA use Node.js built-in `crypto`.
 * ML-DSA-44 uses @noble/post-quantum.
 */
import {
  createSign, createVerify,
  createPrivateKey, createPublicKey,
  sign as nodeSign, verify as nodeVerify,
} from "crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

// sig_alg constants matching the MTA-QR spec and Go implementation.
export const SIG_ALG_MLDSA44    = 1;
export const SIG_ALG_ECDSA_P256 = 4;
export const SIG_ALG_ED25519    = 6;

export interface Signer {
  sign(message: Uint8Array): Uint8Array;
  publicKeyBytes(): Uint8Array;
  readonly sigAlg: number;
  readonly keyName: string; // note verifier key name (without hex_keyid component)
}

/**
 * sigLen returns the expected raw signature byte length for a sig_alg value.
 * MUST be used for note parser dispatch — do not hardcode 64.
 */
export function sigLen(sigAlg: number): number {
  switch (sigAlg) {
    case SIG_ALG_ED25519:    return 64;
    case SIG_ALG_ECDSA_P256: return 64;
    case SIG_ALG_MLDSA44:    return 2420;
    default: return 0;
  }
}

export function sigAlgName(sigAlg: number): string {
  switch (sigAlg) {
    case SIG_ALG_ED25519:    return "Ed25519";
    case SIG_ALG_ECDSA_P256: return "ECDSA-P256";
    case SIG_ALG_MLDSA44:    return "ML-DSA-44";
    default: return `unknown(${sigAlg})`;
  }
}

/** verify dispatches to the correct algorithm. Never infer algorithm from sig length. */
export function verify(
  sigAlg: number,
  message: Uint8Array,
  sig: Uint8Array,
  pubKey: Uint8Array,
): boolean {
  switch (sigAlg) {
    case SIG_ALG_ED25519:    return verifyEd25519(message, sig, pubKey);
    case SIG_ALG_ECDSA_P256: return verifyECDSAP256(message, sig, pubKey);
    case SIG_ALG_MLDSA44:    return verifyMLDSA44(message, sig, pubKey);
    default: return false;
  }
}

// ---- Ed25519 ----

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");

function seedToPrivKey(seed: Uint8Array) {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function rawPubToKeyObj(pub: Uint8Array) {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pub)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function buildKeyName(algLabel: string, _pubBytes: Uint8Array): string {
  // Per c2sp.org/signed-note: key name in signature lines is the bare label.
  return algLabel;
}

export function ed25519FromSeed(seed: Uint8Array): Signer {
  const priv = seedToPrivKey(seed);
  const pub  = createPublicKey(priv);
  const pubBytes = new Uint8Array(
    (pub.export({ format: "der", type: "spki" }) as Buffer).slice(-32)
  );
  return {
    sigAlg: SIG_ALG_ED25519,
    keyName: buildKeyName("ts-issuer-Ed25519", pubBytes),
    sign(message) {
      return new Uint8Array(nodeSign(null, Buffer.from(message), priv) as Buffer);
    },
    publicKeyBytes() { return pubBytes; },
  };
}

export function newEd25519(): Signer {
  const { privateKey: priv, publicKey: pub } = ((): any => {
    const { generateKeyPairSync } = require("crypto");
    return generateKeyPairSync("ed25519");
  })();
  const pubBytes = new Uint8Array(
    (pub.export({ format: "der", type: "spki" }) as Buffer).slice(-32)
  );
  return {
    sigAlg: SIG_ALG_ED25519,
    keyName: buildKeyName("ts-issuer-Ed25519", pubBytes),
    sign(message) {
      return new Uint8Array(nodeSign(null, Buffer.from(message), priv) as Buffer);
    },
    publicKeyBytes() { return pubBytes; },
  };
}

function verifyEd25519(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (pubKey.length !== 32 || sig.length !== 64) return false;
  try {
    const k = rawPubToKeyObj(pubKey);
    return nodeVerify(null, Buffer.from(message), k, Buffer.from(sig));
  } catch { return false; }
}

// ---- ECDSA P-256 ----

function p256ScalarToPrivKey(scalar: Uint8Array) {
  const pkcs8 = Buffer.concat([
    Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex"),
    Buffer.from(scalar),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

export function ecdsaP256FromScalar(scalar: Uint8Array): Signer {
  if (scalar.length !== 32) throw new Error("P-256 scalar must be 32 bytes");
  const priv = p256ScalarToPrivKey(scalar);
  const pub  = createPublicKey(priv);
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  const pubBytes = new Uint8Array(spki.slice(-65));
  return {
    sigAlg: SIG_ALG_ECDSA_P256,
    keyName: buildKeyName("ts-issuer-ECDSA-P256", pubBytes),
    sign(message) {
      const s = createSign("SHA256");
      s.update(Buffer.from(message));
      return derToRaw(s.sign(priv));
    },
    publicKeyBytes() { return pubBytes; },
  };
}

export function newECDSAP256(): Signer {
  const { generateKeyPairSync } = require("crypto");
  const { privateKey: priv, publicKey: pub } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = (pub.export({ format: "der", type: "spki" }) as Buffer);
  const pubBytes = new Uint8Array(spki.slice(-65));
  return {
    sigAlg: SIG_ALG_ECDSA_P256,
    keyName: buildKeyName("ts-issuer-ECDSA-P256", pubBytes),
    sign(message) {
      const s = createSign("SHA256");
      s.update(Buffer.from(message));
      return derToRaw(s.sign(priv));
    },
    publicKeyBytes() { return pubBytes; },
  };
}

function verifyECDSAP256(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (sig.length !== 64 || pubKey.length !== 65 || pubKey[0] !== 0x04) return false;
  try {
    const spki = Buffer.concat([
      Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
      Buffer.from(pubKey),
    ]);
    const pubKeyObj = createPublicKey({ key: spki, format: "der", type: "spki" });
    const v = createVerify("SHA256");
    v.update(Buffer.from(message));
    return v.verify(pubKeyObj, rawToDer(sig));
  } catch { return false; }
}

function rawToDer(raw: Uint8Array): Buffer {
  const r = trimLeadingZeros(raw.slice(0, 32));
  const s = trimLeadingZeros(raw.slice(32, 64));
  const rEnc = r[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), r]) : r;
  const sEnc = s[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), s]) : s;
  const inner = Buffer.concat([
    Buffer.from([0x02, rEnc.length]), rEnc,
    Buffer.from([0x02, sEnc.length]), sEnc,
  ]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

function derToRaw(der: Buffer): Uint8Array {
  let pos = 2;
  if (der[pos] !== 0x02) throw new Error("expected INTEGER tag for r");
  pos++;
  const rLen = der[pos++];
  let r = der.slice(pos, pos + rLen); pos += rLen;
  if (r[0] === 0x00) r = r.slice(1);
  if (der[pos] !== 0x02) throw new Error("expected INTEGER tag for s");
  pos++;
  const sLen = der[pos++];
  let s = der.slice(pos, pos + sLen);
  if (s[0] === 0x00) s = s.slice(1);
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

function trimLeadingZeros(b: Uint8Array | Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return Buffer.from(b.slice(i));
}

// ---- ML-DSA-44 (FIPS 204) ----

export function mlDsa44FromSeed(seed: Uint8Array): Signer {
  if (seed.length !== 32) throw new Error("ML-DSA-44 seed must be 32 bytes");
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const pubBytes = new Uint8Array(publicKey);
  const secKey   = new Uint8Array(secretKey);
  return {
    sigAlg: SIG_ALG_MLDSA44,
    keyName: buildKeyName("ts-issuer-ML-DSA-44", pubBytes),
    sign(message) {
      return new Uint8Array(ml_dsa44.sign(message, secKey));
    },
    publicKeyBytes() { return pubBytes; },
  };
}

export function newMLDSA44(): Signer {
  // Generate a random 32-byte seed
  const { randomBytes } = require("crypto");
  return mlDsa44FromSeed(new Uint8Array(randomBytes(32)));
}

function verifyMLDSA44(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (sig.length !== 2420 || pubKey.length !== 1312) return false;
  try {
    return ml_dsa44.verify(sig, message, pubKey);
  } catch { return false; }
}

