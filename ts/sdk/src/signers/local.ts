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
  Signer, SigAlg,
  SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44,
} from "../signer.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");
const ECDSA_P256_PKCS8_PREFIX = Buffer.from(
  "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex"
);

function buildKeyName(algLabel: string, pubBytes: Uint8Array): string {
  return `${algLabel}+${Buffer.from(pubBytes).toString("base64")}`;
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
export function localEd25519(seed: Uint8Array): Signer {
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
    async sign(message: Uint8Array) {
      return new Uint8Array(nodeSign(null, Buffer.from(message), priv) as Buffer);
    },
    async publicKeyBytes() { return pubBytes; },
  };
}

/** Create a LocalSigner from a 32-byte ECDSA P-256 scalar. */
export function localEcdsaP256(scalar: Uint8Array): Signer {
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
    async sign(message: Uint8Array) {
      const s = createSign("SHA256");
      s.update(Buffer.from(message));
      return derToRaw(s.sign(priv));
    },
    async publicKeyBytes() { return pubBytes; },
  };
}

/** Create a LocalSigner from a 32-byte ML-DSA-44 seed. */
export function localMlDsa44(seed: Uint8Array): Signer {
  if (seed.length !== 32) throw new Error("ML-DSA-44 seed must be 32 bytes");
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const pubBytes = new Uint8Array(publicKey);
  const secKey   = new Uint8Array(secretKey);
  const keyName  = buildKeyName("local-ML-DSA-44", pubBytes);
  return {
    sigAlg: SIG_ALG_ML_DSA_44,
    keyName,
    async sign(message: Uint8Array) {
      return new Uint8Array(ml_dsa44.sign(message, secKey));
    },
    async publicKeyBytes() { return pubBytes; },
  };
}
