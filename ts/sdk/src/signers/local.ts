/**
 * LocalSigner — signs with raw key material held in process memory.
 *
 * FOR TESTING ONLY. Do not use in production. Private key bytes are
 * held in memory and never leave the process, but there is no hardware
 * protection, approval workflow, or audit trail.
 *
 * Use GoodKeySigner for production deployments.
 */

import {
  createSign, sign as nodeSign,
  createPrivateKey, createPublicKey,
} from "crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import {
  LocalSigner,
  SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44,
} from "../signer.js";
import type { Signer, SigAlg } from "../signer.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");
const ECDSA_P256_PKCS8_PREFIX = Buffer.from(
  "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex"
);

function buildKeyName(algLabel: string, _pubBytes: Uint8Array): string {
  // Per c2sp.org/signed-note: the key name in a signature line is the bare name.
  // The key hash and public key go in the trust config verifier key string, not here.
  return algLabel;
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

/** Create a LocalSigner from a 32-byte Ed25519 seed. */
export function localEd25519(seed: Uint8Array): LocalSigner {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const priv  = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pub   = createPublicKey(priv);
  const pubBytes = new Uint8Array(
    (pub.export({ format: "der", type: "spki" }) as Buffer).slice(-32)
  );
  const keyName = buildKeyName("local-Ed25519", pubBytes);
  return {
    sigAlg: SIG_ALG_ED25519,
    keyName,
    sign(message: Uint8Array): Uint8Array {
      return new Uint8Array(nodeSign(null, Buffer.from(message), priv) as Buffer);
    },
    publicKeyBytes(): Uint8Array { return pubBytes; },
  };
}

/** Create a LocalSigner from a 32-byte ECDSA P-256 scalar. */
export function localEcdsaP256(scalar: Uint8Array): LocalSigner {
  if (scalar.length !== 32) throw new Error("P-256 scalar must be 32 bytes");
  const pkcs8 = Buffer.concat([ECDSA_P256_PKCS8_PREFIX, Buffer.from(scalar)]);
  const priv  = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pub   = createPublicKey(priv);
  const spki  = pub.export({ format: "der", type: "spki" }) as Buffer;
  const pubBytes = new Uint8Array(spki.slice(-65));
  const keyName  = buildKeyName("local-ECDSA-P256", pubBytes);
  return {
    sigAlg: SIG_ALG_ECDSA_P256,
    keyName,
    sign(message: Uint8Array): Uint8Array {
      const s = createSign("SHA256");
      s.update(Buffer.from(message));
      return derToRaw(s.sign(priv));
    },
    publicKeyBytes(): Uint8Array { return pubBytes; },
  };
}

/** Create a LocalSigner from a 32-byte ML-DSA-44 seed. */
export function localMlDsa44(seed: Uint8Array): LocalSigner {
  if (seed.length !== 32) throw new Error("ML-DSA-44 seed must be 32 bytes");
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const pubBytes = new Uint8Array(publicKey);
  const secKey   = new Uint8Array(secretKey);
  const keyName  = buildKeyName("local-ML-DSA-44", pubBytes);
  return {
    sigAlg: SIG_ALG_ML_DSA_44,
    keyName,
    sign(message: Uint8Array): Uint8Array {
      return new Uint8Array(ml_dsa44.sign(message, secKey));
    },
    publicKeyBytes(): Uint8Array { return pubBytes; },
  };
}

// ---------------------------------------------------------------------------
// Compatibility aliases matching ts/shared/signing.ts names.
// Used by the HTTP issuer and verifier services.
// ---------------------------------------------------------------------------
import { randomBytes, generateKeyPairSync } from "crypto";

/** Create a LocalSigner from a 32-byte Ed25519 seed (alias for localEd25519). */
export const ed25519FromSeed = localEd25519;

/** Create a LocalSigner from a 32-byte ECDSA P-256 scalar (alias for localEcdsaP256). */
export const ecdsaP256FromScalar = localEcdsaP256;

/** Create a LocalSigner from a 32-byte ML-DSA-44 seed (alias for localMlDsa44). */
export const mlDsa44FromSeed = localMlDsa44;

/** Create an Ed25519 LocalSigner with a freshly generated key pair. */
export function newEd25519(): LocalSigner {
  const { privateKey: priv, publicKey: pub } = generateKeyPairSync("ed25519");
  const pubBytes = new Uint8Array(
    (pub.export({ format: "der", type: "spki" }) as Buffer).slice(-32)
  );
  const keyName = buildKeyName("local-Ed25519", pubBytes);
  return {
    sigAlg: SIG_ALG_ED25519,
    keyName,
    sign(message: Uint8Array): Uint8Array {
      return new Uint8Array(nodeSign(null, Buffer.from(message), priv) as Buffer);
    },
    publicKeyBytes(): Uint8Array { return pubBytes; },
  };
}

/** Create an ECDSA P-256 LocalSigner with a freshly generated key pair. */
export function newECDSAP256(): LocalSigner {
  const { privateKey: priv, publicKey: pub } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = (pub.export({ format: "der", type: "spki" }) as Buffer);
  const pubBytes = new Uint8Array(spki.slice(-65));
  const keyName  = buildKeyName("local-ECDSA-P256", pubBytes);
  return {
    sigAlg: SIG_ALG_ECDSA_P256,
    keyName,
    sign(message: Uint8Array): Uint8Array {
      const s = createSign("SHA256");
      s.update(Buffer.from(message));
      return derToRaw(s.sign(priv));
    },
    publicKeyBytes(): Uint8Array { return pubBytes; },
  };
}

/** Create an ML-DSA-44 LocalSigner with a freshly generated key pair. */
export function newMLDSA44(): LocalSigner {
  return localMlDsa44(new Uint8Array(randomBytes(32)));
}

// Re-export SIG_ALG constants and Signer type for import consolidation.
export { SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44 as SIG_ALG_MLDSA44, sigAlgName } from "../signer.js";
export type { SigAlg } from "../signer.js";
export type { Signer as SignerType, LocalSigner } from "../signer.js";
