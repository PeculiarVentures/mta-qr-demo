/**
 * Signature verification for MTA-QR.
 *
 * Verification is pure crypto — no key custody, no async. Used by the
 * Verifier to check issuer signatures and witness cosignatures in
 * tlog-checkpoint signed notes.
 *
 * Wire format:
 *   Ed25519:     64 bytes
 *   ECDSA P-256: 64 bytes r||s (IEEE P1363)
 *   ML-DSA-44:   2420 bytes (FIPS 204)
 */

import {
  createSign, createVerify,
  createPublicKey, verify as nodeVerify,
} from "crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import {
  SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44, SigAlg,
} from "./signer.js";

const ED25519_SPKI_PREFIX  = Buffer.from("302a300506032b6570032100", "hex");
const ECDSA_P256_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"
);

export function verifySig(
  sigAlg: SigAlg,
  message: Uint8Array,
  sig: Uint8Array,
  pubKey: Uint8Array,
): boolean {
  switch (sigAlg) {
    case SIG_ALG_ED25519:    return verifyEd25519(message, sig, pubKey);
    case SIG_ALG_ECDSA_P256: return verifyEcdsaP256(message, sig, pubKey);
    case SIG_ALG_ML_DSA_44:  return verifyMlDsa44(message, sig, pubKey);
  }
}

function verifyEd25519(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (pubKey.length !== 32 || sig.length !== 64) return false;
  try {
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKey)]);
    const k = createPublicKey({ key: spki, format: "der", type: "spki" });
    return nodeVerify(null, Buffer.from(message), k, Buffer.from(sig));
  } catch { return false; }
}

function verifyEcdsaP256(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (sig.length !== 64 || pubKey.length !== 65 || pubKey[0] !== 0x04) return false;
  try {
    const spki = Buffer.concat([ECDSA_P256_SPKI_PREFIX, Buffer.from(pubKey)]);
    const k = createPublicKey({ key: spki, format: "der", type: "spki" });
    const v = createVerify("SHA256");
    v.update(Buffer.from(message));
    return v.verify(k, rawToDer(sig));
  } catch { return false; }
}

function verifyMlDsa44(message: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): boolean {
  if (sig.length !== 2420 || pubKey.length !== 1312) return false;
  try {
    return ml_dsa44.verify(sig, message, pubKey);
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

function trimLeadingZeros(b: Uint8Array): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return Buffer.from(b.slice(i));
}

// Re-export constants and helpers for callers that import verification only.
export { SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44 } from "./signer.js";
export type { SigAlg } from "./signer.js";

/** Return expected raw signature byte length for sigAlg. */
export function sigAlgSigLen(sigAlg: SigAlg): number {
  switch (sigAlg) {
    case SIG_ALG_ED25519:    return 64;
    case SIG_ALG_ECDSA_P256: return 64;
    case SIG_ALG_ML_DSA_44:  return 2420;
  }
}
