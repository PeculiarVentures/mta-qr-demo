/**
 * Byte encoding/decoding utilities.
 *
 * Pure functions — no crypto, no Node-specific APIs.
 * Safe to use in both Node and browser contexts.
 */

export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex: odd length");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

export function bytesToBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

export function bytesToBase64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

export function base64urlToBytes(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out   = new Uint8Array(total);
  let   pos   = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.length; }
  return out;
}

export function writeBE64(value: bigint): Uint8Array {
  const buf = new DataView(new ArrayBuffer(8));
  buf.setBigUint64(0, value, false);
  return new Uint8Array(buf.buffer);
}

export function readBE64(bytes: Uint8Array, offset: number): bigint {
  return new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(offset, false);
}

export function writeBE16(value: number): Uint8Array {
  const buf = new DataView(new ArrayBuffer(2));
  buf.setUint16(0, value, false);
  return new Uint8Array(buf.buffer);
}

export function readBE16(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset).getUint16(offset, false);
}
