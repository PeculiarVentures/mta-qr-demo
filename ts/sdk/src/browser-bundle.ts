/**
 * MTA-QR SDK — browser bundle.
 *
 * Self-contained browser implementation of the pure protocol functions:
 * CBOR encode/decode, Merkle tree, payload binary codec, byte utilities.
 *
 * Uses Web Crypto (crypto.subtle) for SHA-256 — no Node dependencies.
 * Bundled to an IIFE by esbuild and injected into the demo by build.py.
 *
 * The Node-specific modules (issuer, verifier, signers, checkpoint) are
 * intentionally excluded — the browser demo drives those with Web Crypto directly.
 */

// ── SHA-256 via Web Crypto ─────────────────────────────────────────────────

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await globalThis.crypto.subtle.digest(
    "SHA-256",
    data.buffer as ArrayBuffer
  );
  return new Uint8Array(buf);
}

// ── Byte utilities ─────────────────────────────────────────────────────────

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToBase64(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b));
}

export function bytesToBase64url(b: Uint8Array): string {
  return bytesToBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
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

// ── CBOR encode/decode ─────────────────────────────────────────────────────
// Minimal deterministic CBOR for MTA-QR TBS encoding (RFC 8949 §4.2).
// Supports: unsigned int, text string, array, map (sorted integer keys).

function cborUint(v: number | bigint): Uint8Array {
  const n = typeof v === "bigint" ? v : BigInt(v);
  if (n < 24n)      return new Uint8Array([Number(n)]);
  if (n < 0x100n)   return new Uint8Array([0x18, Number(n)]);
  if (n < 0x10000n) return new Uint8Array([0x19, Number(n >> 8n), Number(n & 0xffn)]);
  if (n < 0x100000000n) {
    const x = Number(n);
    return new Uint8Array([0x1a, x>>>24, (x>>>16)&0xff, (x>>>8)&0xff, x&0xff]);
  }
  const hi = Number(n >> 32n), lo = Number(n & 0xffffffffn);
  return new Uint8Array([0x1b, hi>>>24,(hi>>>16)&0xff,(hi>>>8)&0xff,hi&0xff,
                               lo>>>24,(lo>>>16)&0xff,(lo>>>8)&0xff,lo&0xff]);
}

function cborHeader(majorType: number, v: number | bigint): Uint8Array {
  const h = cborUint(v);
  h[0] |= majorType << 5;
  return h;
}

type CborValue = number | bigint | string | Uint8Array | CborValue[] | Map<number | string, CborValue>;

export function cborEncode(value: CborValue): Uint8Array {
  if (typeof value === "number" || typeof value === "bigint")
    return cborUint(typeof value === "number" ? BigInt(value) : value);
  if (typeof value === "string") {
    const e = new TextEncoder().encode(value);
    return concatBytes(cborHeader(3, e.length), e);
  }
  if (value instanceof Uint8Array)
    return concatBytes(cborHeader(2, value.length), value);
  if (Array.isArray(value)) {
    const parts = [cborHeader(4, value.length)];
    for (const item of value) parts.push(cborEncode(item));
    return concatBytes(...parts);
  }
  if (value instanceof Map) {
    // Sort by CBOR-encoded key length then value (deterministic per RFC 8949 §4.2.1)
    const pairs = [...value.entries()].map(([k, v]) => [cborEncode(k as CborValue), cborEncode(v)] as [Uint8Array, Uint8Array]);
    pairs.sort((a, b) => {
      if (a[0].length !== b[0].length) return a[0].length - b[0].length;
      for (let i = 0; i < a[0].length; i++) if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
      return 0;
    });
    return concatBytes(cborHeader(5, pairs.length), ...pairs.flat());
  }
  throw new Error(`cborEncode: unsupported type '${typeof value}'`);
}

export function cborDecode(bytes: Uint8Array, off = 0): { value: CborValue; end: number } {
  if (off >= bytes.length) throw new Error(`cborDecode: end at ${off}`);
  const ib = bytes[off++];
  const mt = ib >> 5;
  const ai = ib & 0x1f;

  let len: bigint;
  if      (ai < 24)   { len = BigInt(ai); }
  else if (ai === 24) { len = BigInt(bytes[off++]); }
  else if (ai === 25) { len = BigInt(readBE16(bytes, off)); off += 2; }
  else if (ai === 26) { len = BigInt(new DataView(bytes.buffer, bytes.byteOffset).getUint32(off, false)); off += 4; }
  else if (ai === 27) { len = readBE64(bytes, off); off += 8; }
  else throw new Error(`cborDecode: unsupported ai=${ai}`);

  if (mt === 0) return { value: len <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(len) : len, end: off };
  if (mt === 2) { const s = Number(len); return { value: bytes.slice(off, off + s), end: off + s }; }
  if (mt === 3) {
    const s = Number(len);
    return { value: new TextDecoder().decode(bytes.slice(off, off + s)), end: off + s };
  }
  if (mt === 4) {
    const items: CborValue[] = [];
    for (let i = 0; i < Number(len); i++) { const r = cborDecode(bytes, off); items.push(r.value); off = r.end; }
    return { value: items, end: off };
  }
  if (mt === 5) {
    const m = new Map<number | string, CborValue>();
    for (let i = 0; i < Number(len); i++) {
      const k = cborDecode(bytes, off); off = k.end;
      const v = cborDecode(bytes, off); off = v.end;
      m.set(k.value as number | string, v.value);
    }
    return { value: m, end: off };
  }
  throw new Error(`cborDecode: unsupported major type ${mt}`);
}

// ── Merkle tree ─────────────────────────────────────────────────────────────
// BATCH_SIZE=16, OUTER_MAX_BATCHES=16. Domain separation: 0x00=leaf, 0x01=node.

export async function hashLeaf(data: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([0x00]), data));
}

export async function hashNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) throw new Error("merkle: empty");
  let cur = [...leaves];
  while (cur.length > 1) {
    const nxt: Uint8Array[] = [];
    for (let i = 0; i + 1 < cur.length; i += 2) nxt.push(await hashNode(cur[i], cur[i + 1]));
    if (cur.length % 2 === 1) nxt.push(cur[cur.length - 1]);
    cur = nxt;
  }
  return cur[0];
}

export async function merkleProof(leaves: Uint8Array[], idx: number): Promise<Uint8Array[]> {
  const proof: Uint8Array[] = [];
  let cur = [...leaves];
  let i   = idx;
  while (cur.length > 1) {
    const sib = (i % 2 === 0) ? Math.min(i + 1, cur.length - 1) : i - 1;
    proof.push(cur[sib]);
    const nxt: Uint8Array[] = [];
    for (let j = 0; j + 1 < cur.length; j += 2) nxt.push(await hashNode(cur[j], cur[j + 1]));
    if (cur.length % 2 === 1) nxt.push(cur[cur.length - 1]);
    cur = nxt;
    i   = Math.floor(i / 2);
  }
  return proof;
}

export async function computeRootFromProof(
  start: Uint8Array, idx: number, size: number, proof: Uint8Array[]
): Promise<Uint8Array> {
  let node = start;
  let i    = idx;
  let s    = size;
  for (const sib of proof) {
    if (i % 2 === 0) {
      if (i + 1 === s && s % 2 === 1) { i = Math.floor(i / 2); s = Math.ceil(s / 2); continue; }
      node = await hashNode(node, sib);
    } else {
      node = await hashNode(sib, node);
    }
    i = Math.floor(i / 2);
    s = Math.ceil(s / 2);
  }
  return node;
}

export async function verifyInclusion(
  leaf: Uint8Array, idx: number, size: number,
  proof: Uint8Array[], expected: Uint8Array
): Promise<boolean> {
  const computed = await computeRootFromProof(leaf, idx, size, proof);
  // Constant-time comparison via subtle (both are 32 bytes)
  return globalThis.crypto.subtle
    .digest("SHA-256", new Uint8Array(0)) // ensure subtle is warm
    .then(() => {
      if (computed.length !== expected.length) return false;
      let diff = 0;
      for (let i = 0; i < computed.length; i++) diff |= computed[i] ^ expected[i];
      return diff === 0;
    });
}

// ── Payload binary codec ────────────────────────────────────────────────────

export const MODE_EMBEDDED = 0;
export const MODE_CACHED   = 1;
export const MODE_ONLINE   = 2;

export const SIG_ALG_ML_DSA_44  = 1;
export const SIG_ALG_ECDSA_P256 = 4;
export const SIG_ALG_ED25519    = 6;

export interface DecodedPayload {
  mode:           number;
  sigAlg:         number;
  selfDescribing: boolean;
  originId:       bigint;
  treeSize:       bigint;
  entryIndex:     bigint;
  origin:         string | null;
  proofHashes:    Uint8Array[];
  innerProofCount: number;
  tbs:            Uint8Array;
}

export function encodePayload(
  originId: bigint, treeSize: number | bigint, entryIndex: number | bigint,
  innerProof: Uint8Array[], outerProof: Uint8Array[], tbs: Uint8Array,
  sigAlg = SIG_ALG_ED25519, origin?: string, mode = MODE_CACHED
): Uint8Array {
  const selfDescrib = origin !== undefined;
  const flags = (selfDescrib ? 0x80 : 0x00) | ((sigAlg & 0x07) << 2) | (mode & 0x03);
  const parts: Uint8Array[] = [
    new Uint8Array([0x01, flags]),
    writeBE64(originId),
    writeBE64(BigInt(treeSize)),
    writeBE64(BigInt(entryIndex)),
  ];
  if (selfDescrib && origin) {
    const enc = new TextEncoder().encode(origin);
    parts.push(writeBE16(enc.length), enc);
  }
  const allProof = [...innerProof, ...outerProof];
  parts.push(new Uint8Array([allProof.length, innerProof.length]));
  for (const h of allProof) parts.push(h);
  parts.push(writeBE16(tbs.length), tbs);
  return concatBytes(...parts);
}

export function decodePayload(data: Uint8Array): DecodedPayload {
  let pos = 0;
  const rb = () => { if (pos >= data.length) throw new Error(`end at ${pos}`); return data[pos++]; };
  const r2 = () => { const v = readBE16(data, pos); pos += 2; return v; };
  const r8 = () => { const v = readBE64(data, pos); pos += 8; return v; };
  const rn = (n: number) => { if (pos + n > data.length) throw new Error(`need ${n} at ${pos}`); const s = data.slice(pos, pos + n); pos += n; return s; };

  const version = rb();
  if (version !== 0x01) throw new Error(`unsupported version 0x${version.toString(16)}`);
  const flags         = rb();
  const mode          = flags & 0x03;
  const sigAlg        = (flags >> 2) & 0x07;
  const selfDescrib   = (flags & 0x80) !== 0;
  const originId      = r8();
  const treeSize      = r8();
  const entryIndex    = r8();
  const origin        = selfDescrib ? new TextDecoder().decode(rn(r2())) : null;
  const numProof      = rb();
  const innerCount    = rb();
  const proofHashes   = Array.from({ length: numProof }, () => rn(32));
  const tbs           = rn(r2());

  if (pos !== data.length)
    throw new Error(`payload: ${data.length - pos} trailing bytes after TBS`);

  return { mode, sigAlg, selfDescribing: selfDescrib, originId, treeSize,
           entryIndex, origin, proofHashes, innerProofCount: innerCount, tbs };
}

// ── Checkpoint formatting ───────────────────────────────────────────────────

export function fmtCheckpoint(origin: string, treeSize: number, rootHash: Uint8Array): string {
  return `${origin}\n${treeSize}\n${bytesToBase64(rootHash)}\n`;
}

export function fmtCosig(body: string, timestamp: number): string {
  return `cosignature/v1\ntime ${timestamp}\n${body}`;
}

export function computeOriginId(origin: string): bigint {
  // Synchronous — origin ID is computed once at init using sha256 which is async.
  // The demo calls this via the async initOriginId() wrapper below.
  throw new Error("Use initOriginId() — sha256 is async in the browser");
}

export async function initOriginId(origin: string): Promise<bigint> {
  const hash = await sha256(new TextEncoder().encode(origin));
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) id = (id << BigInt(8)) | BigInt(hash[i]);
  return id;
}
