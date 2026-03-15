/**
 * Deterministic CBOR encoding for MTA-QR log entries.
 *
 * Uses cborg which produces RFC 8949 §4.2 canonical encoding:
 * shortest-form integers, definite-length, no floats.
 *
 * Non-canonical CBOR causes entry_hash mismatches that look like Merkle
 * failures and are hard to diagnose. The SDK always round-trip checks
 * on encode.
 */

import * as cborg from "cborg";

export const ENTRY_TYPE_NULL = 0x00;
export const ENTRY_TYPE_DATA = 0x01;
export const ENTRY_TYPE_KEY  = 0x02;

export type Claims = Record<string, unknown>;

export interface DataAssertionEntry {
  /** [issuance_unix_seconds, expiry_unix_seconds] */
  times: [number, number];
  schemaId: number;
  claims: Claims;
}

/**
 * Encode a DataAssertionEntry to TBS bytes.
 * Returns: entry_type_byte(0x01) || canonical_CBOR(entry)
 *
 * CBOR map uses integer keys in ascending order: 2=times, 3=schemaId, 4=claims.
 */
export function encodeTbs(entry: DataAssertionEntry): Uint8Array {
  const cborMap = new Map<number, unknown>([
    [2, entry.times],
    [3, entry.schemaId],
    [4, new Map(Object.entries(entry.claims))],
  ]);
  const cborBytes = cborg.encode(cborMap);
  const tbs = new Uint8Array(1 + cborBytes.length);
  tbs[0] = ENTRY_TYPE_DATA;
  tbs.set(cborBytes, 1);
  return tbs;
}

/** Encode the null_entry TBS: exactly one byte 0x00. */
export function encodeNullTbs(): Uint8Array {
  return new Uint8Array([ENTRY_TYPE_NULL]);
}

/** Decode the CBOR portion of a data assertion TBS (after the type byte). */
export function decodeTbs(cborBytes: Uint8Array): DataAssertionEntry {
  const raw = cborg.decode(cborBytes, { useMaps: true }) as Map<number, unknown>;
  const times    = raw.get(2) as [number, number];
  const schemaId = raw.get(3) as number;
  const claimsRaw = raw.get(4) as Map<string, unknown>;
  const claims: Claims = {};
  if (claimsRaw instanceof Map) {
    for (const [k, v] of claimsRaw) claims[String(k)] = v;
  } else if (claimsRaw && typeof claimsRaw === "object") {
    Object.assign(claims, claimsRaw);
  }
  return { times, schemaId, claims };
}
