/**
 * MTA-QR Issuer.
 *
 * Maintains an in-memory transparency log, issues signed QR code payloads,
 * and publishes cosigned checkpoints. All signing is delegated to the
 * injected Signer — the Issuer never holds key material.
 *
 * Witness keys are ephemeral Ed25519 keys generated at startup. In a future
 * release these will optionally be managed by GoodKey.
 */

import { randomBytes } from "crypto";
import { Signer } from "./signer.js";
import { encodeTbs, encodeNullTbs, DataAssertionEntry, Claims } from "./cbor.js";
import { entryHash, inclusionProof, computeRoot } from "./merkle.js";
import {
  checkpointBody, signCheckpointBody, signCosignature,
  noteKeyId, witnessKeyId, computeOriginId, pubKeyFromSeed, generateSeed,
} from "./checkpoint.js";
import {
  encodePayload, WitnessCosig, MODE_CACHED, MODE_ONLINE,
} from "./payload.js";

export interface IssuerConfig {
  /** Log origin string. Must be globally unique per (key, algorithm) pair. */
  origin: string;
  /** Schema ID included in every issued assertion. */
  schemaId: number;
  /**
   * Payload mode.
   *   1 = Mode 1 (default): inclusion proof embedded at issuance time.
   *       Verifier works fully offline after a one-time checkpoint prefetch.
   *   2 = Mode 2: no proof embedded. A production scanner fetches the proof
   *       from a tile server at scan time using entryIndex + treeSize.
   *       WARNING: this SDK's Verifier does NOT perform that fetch — it
   *       validates everything except inclusion. Use Mode 2 only if you are
   *       building a scanner that implements tile fetching independently.
   * Defaults to 1.
   */
  mode?: 1 | 2;
  /**
   * Number of witness cosignatures to include.
   * Defaults to 2.
   */
  witnessCount?: number;
  /**
   * Batch size for the tiled two-level Merkle tree.
   * Must match the verifier. Defaults to 16.
   */
  batchSize?: number;
}

export interface IssuedQR {
  /** Zero-based index of this entry in the log. */
  entryIndex: number;
  /** Total number of entries in the log at issuance time. */
  treeSize: number;
  /** Raw payload bytes — encode this into a QR code. */
  payload: Uint8Array;
  /** payload as a base64url string, ready for use in a URL or QR code. */
  payloadB64url: string;
}

interface WitnessKey {
  name:  string;
  keyId: Uint8Array;
  pub:   Uint8Array;
  seed:  Uint8Array;
}

interface LogEntry {
  index: number;
  tbs:   Uint8Array;
  hash:  Uint8Array;
}

interface Batch {
  entries: LogEntry[];
  root:    Uint8Array;
}

interface SignedCheckpoint {
  treeSize:  number;
  rootHash:  Uint8Array;
  body:      Uint8Array;
  issuerSig: Uint8Array;
  cosigs:    WitnessCosig[];
}

export class Issuer {
  private readonly origin:      string;
  private readonly originId:    bigint;
  private readonly schemaId:    number;
  private readonly mode:        1 | 2;
  private readonly batchSize:   number;
  private readonly signer:      Signer;
  private readonly witnesses:   WitnessKey[];

  private batches:       Batch[]    = [];
  private currentBatch:  LogEntry[] = [];
  private latestCkpt:    SignedCheckpoint | null = null;
  private sigAlg:        number     = 0;
  private issuerPub:     Uint8Array = new Uint8Array(0);
  private issuerKeyId:   Uint8Array = new Uint8Array(4);
  private initialized:   boolean    = false;

  constructor(config: IssuerConfig, signer: Signer) {
    this.origin    = config.origin;
    this.originId  = computeOriginId(config.origin);
    this.schemaId  = config.schemaId;
    this.mode      = config.mode ?? 1;
    this.batchSize = config.batchSize ?? 16;
    this.signer    = signer;

    const count = config.witnessCount ?? 2;
    this.witnesses = Array.from({ length: count }, (_, i) => {
      const seed = generateSeed();
      const pub  = pubKeyFromSeed(seed);
      const name = `witness-${i}`;
      return { name, keyId: witnessKeyId(name, pub), pub, seed };
    });
  }

  /**
   * Initialize the issuer. Must be called before issue().
   * Resolves the signing key's public key and algorithm, appends the
   * genesis null_entry, and publishes the first checkpoint.
   */
  async init(): Promise<void> {
    if (this.initialized) return;
    this.sigAlg    = this.signer.sigAlg;
    this.issuerPub = await this.signer.publicKeyBytes();
    // Per c2sp.org/signed-note: key_id = SHA-256(name||0x0A||0x01||pub)[0:4]
    this.issuerKeyId = noteKeyId(this.signer.keyName, this.issuerPub);
    this.appendEntry(encodeNullTbs());
    await this.publishCheckpoint();
    this.initialized = true;
  }

  /**
   * Issue a QR code payload for a set of claims.
   *
   * @param claims  Key-value claims to include in the assertion.
   * @param ttlSeconds  How long the assertion is valid for. Defaults to 3600.
   */
  async issue(claims: Claims, ttlSeconds = 3600): Promise<IssuedQR> {
    if (!this.initialized) throw new Error("Issuer: call init() before issue()");

    const now    = Math.floor(Date.now() / 1000);
    const expiry = now + ttlSeconds;
    const entry: DataAssertionEntry = {
      times: [now, expiry],
      schemaId: this.schemaId,
      claims,
    };

    const tbs      = encodeTbs(entry);
    const idx      = this.appendEntry(tbs);
    await this.publishCheckpoint();
    const payload  = this.buildPayload(idx, tbs);

    return {
      entryIndex:   idx,
      treeSize:     this.latestCkpt!.treeSize,
      payload,
      payloadB64url: Buffer.from(payload).toString("base64url"),
    };
  }

  /**
   * Return the trust config JSON for this issuer.
   * Save this to a file and give it to verifiers.
   */
  trustConfigJson(checkpointUrl: string): string {
    if (!this.initialized) throw new Error("Issuer: call init() before trustConfigJson()");
    return JSON.stringify({
      origin:             this.origin,
      origin_id:          this.originId.toString(16).padStart(16, "0"),
      issuer_key_name:    this.signer.keyName,
      issuer_pub_key_hex: Buffer.from(this.issuerPub).toString("hex"),
      sig_alg:            this.sigAlg,
      witness_quorum:     this.witnesses.length,
      checkpoint_url:     checkpointUrl,
      witnesses: this.witnesses.map(w => ({
        name:        w.name,
        key_id_hex:  Buffer.from(w.keyId).toString("hex"),
        pub_key_hex: Buffer.from(w.pub).toString("hex"),
      })),
    }, null, 2);
  }

  /** The current signed checkpoint note (tlog-checkpoint signed-note format). */
  checkpointNote(): string {
    if (!this.latestCkpt) throw new Error("Issuer: not initialized");
    const ckpt = this.latestCkpt;
    let note = Buffer.from(ckpt.body).toString() + "\n";
    // Per c2sp.org/signed-note: base64 payload = 4-byte key_hash || raw_signature
    const issuerPayload = new Uint8Array(4 + ckpt.issuerSig.length);
    issuerPayload.set(this.issuerKeyId, 0);
    issuerPayload.set(ckpt.issuerSig, 4);
    note += `— ${this.signer.keyName} ${Buffer.from(issuerPayload).toString("base64")}\n`;
    for (let i = 0; i < this.witnesses.length; i++) {
      const w = this.witnesses[i];
      const c = ckpt.cosigs[i];
      // Per c2sp.org/signed-note: 4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig
      const payload = new Uint8Array(76);
      payload.set(w.keyId, 0);
      let tsVal = c.timestamp;
      for (let j = 7; j >= 0; j--) { payload[4 + j] = Number(tsVal & BigInt(0xff)); tsVal >>= BigInt(8); }
      payload.set(c.signature, 12);
      note += `— ${w.name} ${Buffer.from(payload).toString("base64")}\n`;
    }
    return note;
  }

  // --- private ---

  private totalEntries(): number {
    return this.batches.reduce((n, b) => n + b.entries.length, 0) + this.currentBatch.length;
  }

  private batchRoots(): Uint8Array[] {
    const roots = this.batches.map(b => b.root);
    if (this.currentBatch.length > 0) {
      roots.push(computeRoot(this.currentBatch.map(e => e.hash)));
    }
    return roots;
  }

  private appendEntry(tbs: Uint8Array): number {
    const idx = this.totalEntries();
    const hash = entryHash(tbs);
    this.currentBatch.push({ index: idx, tbs, hash });
    if (this.currentBatch.length >= this.batchSize) {
      const root = computeRoot(this.currentBatch.map(e => e.hash));
      this.batches.push({ entries: this.currentBatch, root });
      this.currentBatch = [];
    }
    return idx;
  }

  private async publishCheckpoint(): Promise<void> {
    const parentRoot = computeRoot(this.batchRoots());
    const treeSize   = this.totalEntries();
    const body       = checkpointBody(this.origin, BigInt(treeSize), parentRoot);
    const issuerSig  = await this.signer.sign(body);
    const ts         = BigInt(Math.floor(Date.now() / 1000));
    const cosigs: WitnessCosig[] = this.witnesses.map(w => {
      const sig = signCosignature(body, ts, w.seed);
      const s64 = new Uint8Array(64);
      s64.set(sig);
      return { keyId: w.keyId, timestamp: ts, signature: s64 };
    });
    this.latestCkpt = { treeSize, rootHash: parentRoot, body, issuerSig, cosigs };
  }

  private buildPayload(entryIdx: number, tbs: Uint8Array): Uint8Array {
    const ckpt = this.latestCkpt!;
    

    // Mode 2: no proof embedded — verifier fetches proof at scan time.
    if (this.mode === 2) {
      return encodePayload({
        version: 0x01,
        mode: MODE_ONLINE,
        sigAlg: this.sigAlg,
        dualSig: false,
        selfDescrib: true,
        originId:   this.originId,
        treeSize:   BigInt(ckpt.treeSize),
        entryIndex: BigInt(entryIdx),
        origin:     this.origin,
        proofHashes:     [],
        innerProofCount: 0,
        tbs,
      });
    }

    // Mode 1: embed two-phase tiled inclusion proof.
    const batchIdx = Math.floor(entryIdx / this.batchSize);
    const innerIdx = entryIdx % this.batchSize;

    let batchHashes: Uint8Array[];
    let batchSz: number;
    if (batchIdx < this.batches.length) {
      batchHashes = this.batches[batchIdx].entries.map(e => e.hash);
      batchSz     = this.batches[batchIdx].entries.length;
    } else {
      batchHashes = this.currentBatch.map(e => e.hash);
      batchSz     = this.currentBatch.length;
    }

    const innerProof = inclusionProof(batchHashes, innerIdx, batchSz);
    const allRoots   = this.batchRoots();
    const outerProof = inclusionProof(allRoots, batchIdx, allRoots.length);

    return encodePayload({
      version: 0x01,
      mode: MODE_CACHED,
      sigAlg: this.sigAlg,
      dualSig: false,
      selfDescrib: true,
      originId:   this.originId,
      treeSize:   BigInt(ckpt.treeSize),
      entryIndex: BigInt(entryIdx),
      origin:     this.origin,
      proofHashes:     [...innerProof, ...outerProof],
      innerProofCount: innerProof.length,
      tbs,
    });
  }
}
