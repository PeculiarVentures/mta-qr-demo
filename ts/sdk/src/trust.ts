/**
 * Trust configuration for MTA-QR verifiers.
 *
 * Loaded from the filesystem at startup. The verifier needs this to know
 * which issuers to trust, which algorithms they use, and where to fetch
 * checkpoints for Merkle proof verification.
 *
 * File format is JSON, matching the issuer's /trust-config endpoint response
 * so configs can be captured from a running issuer and deployed to verifiers.
 */

import { readFileSync } from "fs";
import { sha256 } from "./hash.js";
import { SigAlg, SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_ML_DSA_44 } from "./signer.js";

export interface WitnessEntry {
  name: string;
  keyIdHex: string;
  pubKeyHex: string;
  /** Decoded from keyIdHex on load. */
  keyId: Uint8Array;
  /** Decoded from pubKeyHex on load. */
  pubKey: Uint8Array;
}

export interface TrustConfig {
  /** Log origin string. Unique per (key, algorithm) pair. */
  origin: string;
  /** First 8 bytes of SHA-256(origin) as big-endian uint64. */
  originId: bigint;
  /** Key name prefix used to identify the issuer sig line in a signed note. */
  issuerKeyName: string;
  /** Raw public key bytes of the issuer. */
  issuerPubKey: Uint8Array;
  /** Wire algorithm identifier. */
  sigAlg: SigAlg;
  /** Minimum number of witness cosignatures required. */
  witnessQuorum: number;
  witnesses: WitnessEntry[];
  /** URL of the issuer's /checkpoint endpoint. */
  checkpointUrl: string;
}

/** Raw JSON shape written by the issuer's /trust-config endpoint. */
interface TrustConfigJSON {
  origin: string;
  origin_id: string;
  issuer_key_name: string;
  issuer_pub_key_hex: string;
  sig_alg: number;
  witness_quorum: number;
  checkpoint_url: string;
  witnesses: Array<{
    name: string;
    key_id_hex: string;
    pub_key_hex: string;
  }>;
}

function parseSigAlg(n: number): SigAlg {
  if (n === SIG_ALG_ML_DSA_44)  return SIG_ALG_ML_DSA_44;
  if (n === SIG_ALG_ECDSA_P256) return SIG_ALG_ECDSA_P256;
  if (n === SIG_ALG_ED25519)    return SIG_ALG_ED25519;
  throw new Error(`trust-config: unrecognized sig_alg ${n}`);
}

function fromJSON(raw: TrustConfigJSON): TrustConfig {
  const originId = BigInt("0x" + raw.origin_id);
  const issuerPubKey = Uint8Array.from(Buffer.from(raw.issuer_pub_key_hex, "hex"));
  const witnesses: WitnessEntry[] = raw.witnesses.map(w => ({
    name: w.name,
    keyIdHex: w.key_id_hex,
    pubKeyHex: w.pub_key_hex,
    keyId:  Uint8Array.from(Buffer.from(w.key_id_hex, "hex")),
    pubKey: Uint8Array.from(Buffer.from(w.pub_key_hex, "hex")),
  }));
  const witnessQuorum = raw.witness_quorum;
  if (!Number.isInteger(witnessQuorum) || witnessQuorum < 1) {
    throw new Error(
      `trust config: witness_quorum must be a positive integer, got ${witnessQuorum}`
    );
  }
  if (witnessQuorum > witnesses.length) {
    throw new Error(
      `trust config: witness_quorum (${witnessQuorum}) exceeds witness count (${witnesses.length})`
    );
  }
  return {
    origin: raw.origin,
    originId,
    issuerKeyName: raw.issuer_key_name,
    issuerPubKey,
    sigAlg: parseSigAlg(raw.sig_alg),
    witnessQuorum,
    witnesses,
    checkpointUrl: raw.checkpoint_url,
  };
}

/**
 * Load a TrustConfig from a JSON file on the filesystem.
 *
 * The file must match the shape produced by an issuer's /trust-config endpoint.
 * Intended to be called once at startup, not on every verification.
 *
 * @example
 * const trust = loadTrustConfigFile("./trust/my-issuer.json");
 * const verifier = new Verifier(trust);
 */
export function loadTrustConfigFile(path: string): TrustConfig {
  let raw: TrustConfigJSON;
  try {
    raw = JSON.parse(readFileSync(path, "utf-8")) as TrustConfigJSON;
  } catch (e) {
    throw new Error(`trust-config: failed to read ${path}: ${e}`);
  }
  return fromJSON(raw);
}

/**
 * Parse a TrustConfig from a JSON string.
 * Useful when the consumer fetches the trust config themselves
 * or embeds it as a constant.
 */
export function parseTrustConfig(json: string): TrustConfig {
  let raw: TrustConfigJSON;
  try {
    raw = JSON.parse(json) as TrustConfigJSON;
  } catch (e) {
    throw new Error(`trust-config: invalid JSON: ${e}`);
  }
  return fromJSON(raw);
}

/**
 * Compute the origin_id for a given origin string.
 * First 8 bytes of SHA-256(origin) interpreted as big-endian uint64.
 */
export function computeOriginId(origin: string): bigint {
  const h = sha256(new TextEncoder().encode(origin));
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) {
    id = (id << BigInt(8)) | BigInt(h[i]);
  }
  return id;
}
