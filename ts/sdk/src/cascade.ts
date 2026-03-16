/**
 * MTA-QR Bloom filter cascade for revocation.
 *
 * Wire format, construction parameters, and query algorithm are normatively
 * defined in SPEC.md §Revocation — Normative Construction Parameters.
 * All constants MUST match the spec exactly.
 */

import { sha256 } from "./hash.js";

// Construction constants — normative per SPEC.md §Revocation.
const BITS_PER_ELEMENT = 1.4427; // = 1/ln(2); optimal for k=1 at ~50% FPR
const MIN_FILTER_BITS = 8;       // 1 byte minimum; preserves ~50% FPR for n=1
const MAX_LEVELS = 32;           // fail if cascade does not terminate by this depth

interface Level {
  bitCount: number;
  bits: Uint8Array; // MSB-first: bit i in byte i>>3 at position 7-(i&7)
}

/** Bloom filter cascade over revoked/valid entry index sets. */
export class Cascade {
  private readonly levels: Level[];

  private constructor(levels: Level[]) {
    this.levels = levels;
  }

  /**
   * Build a cascade over (revoked, valid) entry index sets.
   * Returns an empty cascade (num_levels=0) if revoked is empty.
   */
  static build(revoked: bigint[], valid: bigint[]): Cascade {
    if (revoked.length === 0) return new Cascade([]);

    // Sorted copies for deterministic insertion order.
    let include = [...revoked].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    let exclude = [...valid].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    const levels: Level[] = [];

    for (let levelIdx = 0; levelIdx < MAX_LEVELS; levelIdx++) {
      if (include.length === 0) break;

      const m = filterSize(include.length);
      const bits = new Uint8Array(m >> 3);

      for (const x of include) {
        const b = bitPosition(x, levelIdx, m);
        bits[b >> 3] |= 1 << (7 - (b & 7));
      }

      levels.push({ bitCount: m, bits });

      const fp: bigint[] = [];
      for (const x of exclude) {
        const b = bitPosition(x, levelIdx, m);
        if ((bits[b >> 3] >> (7 - (b & 7))) & 1) fp.push(x);
      }

      [include, exclude] = [fp, include];
    }

    if (include.length !== 0) {
      throw new Error(`cascade: did not terminate within ${MAX_LEVELS} levels`);
    }

    return new Cascade(levels);
  }

  /**
   * Returns true if entry_index is revoked.
   * False positives possible; false negatives impossible (given correct build inputs).
   */
  query(x: bigint): boolean {
    if (this.levels.length === 0) return false;
    let result = false;
    for (let i = 0; i < this.levels.length; i++) {
      const lv = this.levels[i];
      const b = bitPosition(x, i, lv.bitCount);
      const inFilter = ((lv.bits[b >> 3] >> (7 - (b & 7))) & 1) === 1;
      if (i === 0) {
        if (!inFilter) return false; // definitely not revoked
        result = true;
      } else {
        if (inFilter) result = !result;
        else return result;
      }
    }
    return result;
  }

  /** Serialize per SPEC.md §Revocation — Binary Encoding. */
  encode(): Uint8Array {
    const parts: Uint8Array[] = [];
    parts.push(new Uint8Array([this.levels.length]));
    for (const lv of this.levels) {
      const hdr = new Uint8Array(5);
      new DataView(hdr.buffer).setUint32(0, lv.bitCount, false); // big-endian
      hdr[4] = 1; // k=1
      parts.push(hdr);
      parts.push(lv.bits);
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let pos = 0;
    for (const p of parts) { out.set(p, pos); pos += p.length; }
    return out;
  }

  /** Deserialize from bytes produced by encode(). */
  static decode(b: Uint8Array): Cascade {
    if (b.length === 0) throw new Error("cascade: empty input");
    const numLevels = b[0];
    let pos = 1;
    const levels: Level[] = [];
    for (let i = 0; i < numLevels; i++) {
      if (pos + 5 > b.length) throw new Error(`cascade: truncated at level ${i} header`);
      const dv = new DataView(b.buffer, b.byteOffset + pos);
      const bitCount = dv.getUint32(0, false); // big-endian
      const k = b[pos + 4];
      pos += 5;
      if (k !== 1) throw new Error(`cascade: level ${i} has k=${k}, MUST be 1`);
      if (bitCount === 0) throw new Error(`cascade: level ${i} has bit_count=0`);
      const byteCount = (bitCount + 7) >> 3;
      if (pos + byteCount > b.length) throw new Error(`cascade: truncated at level ${i} bit array`);
      const bits = b.slice(pos, pos + byteCount);
      pos += byteCount;
      levels.push({ bitCount, bits });
    }
    if (pos !== b.length) throw new Error(`cascade: ${b.length - pos} trailing bytes`);
    return new Cascade(levels);
  }
}

/**
 * bit_position(x, i) = big_endian_uint64(SHA-256(x_bytes || uint8(i))[0:8]) mod m
 * x_bytes is entry_index as 8-byte big-endian uint64.
 */
function bitPosition(x: bigint, levelIdx: number, m: number): number {
  const buf = new Uint8Array(9);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, x, false); // big-endian
  buf[8] = levelIdx;
  const h = sha256(buf);
  // Read first 8 bytes as big-endian uint64, mod m.
  const hi = new DataView(h.buffer, h.byteOffset).getUint32(0, false);
  const lo = new DataView(h.buffer, h.byteOffset).getUint32(4, false);
  const v = BigInt(hi) * 0x100000000n + BigInt(lo);
  return Number(v % BigInt(m));
}

/** Bit array size: max(ceil(n * 1.4427), 8) rounded up to byte boundary. */
function filterSize(n: number): number {
  const m = Math.max(Math.ceil(n * BITS_PER_ELEMENT), MIN_FILTER_BITS);
  return (m + 7) & ~7; // round up to byte boundary
}
