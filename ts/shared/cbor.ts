/**
 * Deterministic CBOR encoding for MTA-QR log entries.
 * Uses cborg which produces RFC 8949 §4.2 canonical encoding by default:
 * shortest-form integer encoding, definite-length, no floats.
 *
 * Non-canonical CBOR causes entry_hash mismatches that look like Merkle
 * failures — hard to diagnose. Always verify with roundTripCanonical.
 */
import * as cborg from "cborg";

export const ENTRY_TYPE_NULL = 0x00;
export const ENTRY_TYPE_DATA = 0x01;
export const ENTRY_TYPE_KEY  = 0x02;

export interface DataAssertionLogEntry {
  times: [number, number];  // [issuance_time, expiry_time]
  schemaId: number;
  claims: Record<string, unknown>;
}

/**
 * Encode a DataAssertionLogEntry to TBS bytes.
 * Returns entry_type_byte || canonical_CBOR(entry).
 * CBOR map uses integer keys: 2=[times], 3=schemaId, 4=claims.
 * Key ordering must be ascending: 2, 3, 4.
 */
export function encodeDataAssertion(entry: DataAssertionLogEntry): Uint8Array {
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

/** Encode a null_entry TBS: exactly one byte 0x00. */
export function encodeNullEntry(): Uint8Array {
  return new Uint8Array([ENTRY_TYPE_NULL]);
}

/** Decode the CBOR portion of a data assertion TBS (after the type byte). */
export function decodeDataAssertion(cborBytes: Uint8Array): DataAssertionLogEntry {
  const raw = cborg.decode(cborBytes, { useMaps: true }) as Map<number, unknown>;
  const times = raw.get(2) as [number, number];
  const schemaId = raw.get(3) as number;
  const claimsRaw = raw.get(4) as Map<string, unknown>;
  const claims: Record<string, unknown> = {};
  if (claimsRaw instanceof Map) {
    for (const [k, v] of claimsRaw) claims[String(k)] = v;
  } else if (claimsRaw && typeof claimsRaw === "object") {
    Object.assign(claims, claimsRaw);
  }
  return { times, schemaId, claims };
}

/**
 * Round-trip canonicalization check. Decode and re-encode; verify identical bytes.
 * Issuers should call this in their issuance pipeline.
 */
export function roundTripCanonical(cborBytes: Uint8Array): void {
  const decoded = cborg.decode(cborBytes);
  const reencoded = cborg.encode(decoded);
  const a = Buffer.from(cborBytes).toString("hex");
  const b = Buffer.from(reencoded).toString("hex");
  if (a !== b) {
    throw new Error(`cbor: not canonical: input=${a} reencoded=${b}`);
  }
}
