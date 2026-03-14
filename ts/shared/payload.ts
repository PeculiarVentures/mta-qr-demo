/**
 * MTAQRPayload binary encoding and decoding.
 * Big-endian integers. All length fields bounds-checked before reading.
 * Must produce identical byte sequences to the Go implementation.
 */

export const MODE_EMBEDDED = 0;
export const MODE_CACHED   = 1;
export const MODE_ONLINE   = 2;

export const SIG_ALG_FN_DSA_512  = 0;
export const SIG_ALG_ML_DSA_44   = 1;
export const SIG_ALG_ML_DSA_65   = 2;
export const SIG_ALG_SLH_DSA_128S = 3;
export const SIG_ALG_ECDSA_P256  = 4;
export const SIG_ALG_ECDSA_P384  = 5;
export const SIG_ALG_ED25519     = 6;

export interface WitnessCosig {
  keyID:     Uint8Array; // 4 bytes
  timestamp: bigint;     // uint64
  signature: Uint8Array; // 64 bytes
}

export interface Payload {
  version:     number;  // 0x01
  mode:        number;  // 0-2
  sigAlg:      number;  // 0-6
  dualSig:     boolean;
  selfDescrib: boolean;

  originID:   bigint;
  treeSize:   bigint;
  entryIndex: bigint;

  origin?:     string;    // self-describing mode only

  // Tiled proof: proofHashes = innerProof ++ outerProof.
  // innerProofCount is the split point.
  proofHashes:     Uint8Array[]; // each 32 bytes; empty for mode 2
  innerProofCount: number;       // how many leading proofHashes are the inner (batch) proof

  tbs:         Uint8Array;

  // Mode 0 only
  rootHash?:  Uint8Array; // 32 bytes
  issuerSig?: Uint8Array;
  cosigs?:    WitnessCosig[];
}

// --- Encoder ---

export function encode(p: Payload): Uint8Array {
  validate(p);
  const parts: Uint8Array[] = [];

  const push = (b: Uint8Array) => parts.push(b);
  const pushByte = (v: number) => push(new Uint8Array([v]));
  const pushU16 = (v: number) => {
    const b = new Uint8Array(2);
    b[0] = (v >> 8) & 0xff; b[1] = v & 0xff;
    push(b);
  };
  const pushU64 = (v: bigint) => {
    const b = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { b[i] = Number(v & BigInt(0xff)); v >>= BigInt(8); }
    push(b);
  };

  pushByte(p.version);

  let flags = p.mode & 0x03;
  flags |= (p.sigAlg & 0x07) << 2;
  if (p.dualSig)    flags |= 0x20;
  if (p.selfDescrib) flags |= 0x80;
  pushByte(flags);

  pushU64(p.originID);
  pushU64(p.treeSize);
  pushU64(p.entryIndex);

  if (p.selfDescrib && p.origin !== undefined) {
    const originBytes = new TextEncoder().encode(p.origin);
    pushU16(originBytes.length);
    push(originBytes);
  }

  pushByte(p.proofHashes.length);
  pushByte(p.innerProofCount);
  for (const h of p.proofHashes) push(h);

  pushU16(p.tbs.length);
  push(p.tbs);

  if (p.mode === MODE_EMBEDDED) {
    push(p.rootHash!);
    pushU16(p.issuerSig!.length);
    push(p.issuerSig!);
    pushByte(p.cosigs!.length);
    for (const c of p.cosigs!) {
      push(c.keyID);
      pushU64(c.timestamp);
      push(c.signature);
    }
  }

  const total = parts.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of parts) { out.set(b, offset); offset += b.length; }
  return out;
}

// --- Decoder ---

export function decode(data: Uint8Array): Payload {
  const r = new Reader(data);

  const version = r.byte("version");
  if (version !== 0x01) throw new Error(`payload: unsupported version 0x${version.toString(16)}`);

  const flags = r.byte("flags");
  const mode        = flags & 0x03;
  const sigAlg      = (flags >> 2) & 0x07;
  const dualSig     = (flags & 0x20) !== 0;
  const selfDescrib = (flags & 0x80) !== 0;

  if (mode > 2)  throw new Error(`payload: invalid mode ${mode}`);
  if (sigAlg > 6) throw new Error(`payload: unrecognized sig_alg ${sigAlg}`);

  const originID   = r.u64("origin_id");
  const treeSize   = r.u64("tree_size");
  const entryIndex = r.u64("entry_index");

  let origin: string | undefined;
  if (selfDescrib) {
    const originLen = r.u16("origin_len");
    origin = new TextDecoder().decode(r.bytes(originLen, "origin"));
  }

  const numProof = r.byte("proof_count");
  if (mode === MODE_ONLINE && numProof !== 0) {
    throw new Error(`payload: Mode 2 must have proof_count=0, got ${numProof}`);
  }
  const innerProofCount = r.byte("inner_proof_count");
  if (innerProofCount > numProof) {
    throw new Error(`payload: inner_proof_count(${innerProofCount}) > proof_count(${numProof})`);
  }
  const proofHashes: Uint8Array[] = [];
  for (let i = 0; i < numProof; i++) {
    proofHashes.push(r.bytes(32, `proof[${i}]`));
  }

  const tbsLen = r.u16("tbs_len");
  if (tbsLen === 0) throw new Error("payload: tbs_len must be >= 1");
  const tbs = r.bytes(tbsLen, "tbs");

  const p: Payload = {
    version, mode, sigAlg, dualSig, selfDescrib,
    originID, treeSize, entryIndex, origin,
    proofHashes, innerProofCount, tbs,
  };

  if (mode === MODE_EMBEDDED) {
    p.rootHash  = r.bytes(32, "root_hash");
    const sigLen = r.u16("issuer_sig_len");
    p.issuerSig = r.bytes(sigLen, "issuer_sig");
    const cosigCount = r.byte("witness_count");
    p.cosigs = [];
    for (let i = 0; i < cosigCount; i++) {
      const keyID    = r.bytes(4, `cosig[${i}].key_id`);
      const timestamp = r.u64(`cosig[${i}].timestamp`);
      const signature = r.bytes(64, `cosig[${i}].signature`);
      p.cosigs.push({ keyID, timestamp, signature });
    }
  }

  if (r.remaining() !== 0) {
    throw new Error(`payload: ${r.remaining()} trailing bytes`);
  }

  return p;
}

// --- helpers ---

function validate(p: Payload): void {
  if (p.version !== 0x01) throw new Error("payload: version must be 0x01");
  if (p.mode > 2)         throw new Error(`payload: invalid mode ${p.mode}`);
  if (p.sigAlg > 6)       throw new Error(`payload: unrecognized sig_alg ${p.sigAlg}`);
  if (p.tbs.length === 0) throw new Error("payload: tbs must not be empty");
  if (p.mode === MODE_ONLINE && p.proofHashes.length !== 0) {
    throw new Error("payload: Mode 2 must have empty proofHashes");
  }
  if (p.mode === MODE_EMBEDDED) {
    if (!p.rootHash || p.rootHash.length !== 32) throw new Error("payload: rootHash must be 32 bytes");
    if (!p.issuerSig) throw new Error("payload: issuerSig required for Mode 0");
    if (!p.cosigs)    throw new Error("payload: cosigs required for Mode 0");
  }
}

class Reader {
  private pos = 0;
  constructor(private data: Uint8Array) {}

  remaining(): number { return this.data.length - this.pos; }

  byte(field: string): number {
    if (this.pos >= this.data.length) {
      throw new Error(`payload: unexpected end at ${field} (offset ${this.pos})`);
    }
    return this.data[this.pos++];
  }

  bytes(n: number, field: string): Uint8Array {
    if (this.pos + n > this.data.length) {
      throw new Error(`payload: need ${n} bytes for ${field} at offset ${this.pos}, only ${this.data.length - this.pos} remaining`);
    }
    const b = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }

  u16(field: string): number {
    const b = this.bytes(2, field);
    return (b[0] << 8) | b[1];
  }

  u64(field: string): bigint {
    const b = this.bytes(8, field);
    let v = BigInt(0);
    for (let i = 0; i < 8; i++) v = (v << BigInt(8)) | BigInt(b[i]);
    return v;
  }
}
