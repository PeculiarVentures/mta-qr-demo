/**
 * MTA-QR Verifier.
 *
 * Verifies QR code payloads against a loaded TrustConfig. No key custody
 * required — verification is pure crypto.
 *
 * **Mode 2 limitation:** For Mode 2 (online) payloads this verifier does NOT
 * verify Merkle inclusion. Mode 2 payloads carry no embedded proof — inclusion
 * is meant to be verified at scan time by fetching proof tiles from a tile server.
 * This SDK has no tile server. `verify()` on a Mode 2 payload validates everything
 * else (checkpoint, witnesses, TBS, expiry) but returns `valid: true` without
 * cryptographic proof that the entry is in the log. If you need that guarantee,
 * use Mode 1, or implement tile fetching on top of this library.
 *
 * Checkpoint fetching is done on demand and cached by (origin, treeSize).
 * Trust config is loaded from the filesystem at construction time.
 */

import { TrustConfig } from "./trust.js";
import { decodePayload, MODE_ONLINE } from "./payload.js";
import { decodeTbs, ENTRY_TYPE_DATA } from "./cbor.js";
import { entryHash, verifyInclusion, computeRootFromProof } from "./merkle.js";
import {
  parseCheckpointBody, verifyCosignature, cosignatureMessage,
} from "./checkpoint.js";
import { verifySig } from "./verify-sig.js";
import { SIG_ALG_ED25519 } from "./signer.js";
import { Claims } from "./cbor.js";
import { Cascade } from "./cascade.js";

// --- Result types ---

export interface VerifyOk {
  valid: true;
  /** Payload mode. 1 = Mode 1 (inclusion proof verified). 2 = Mode 2
   *  (inclusion NOT verified — proof must be fetched from a tile server). */
  mode:       number;
  entryIndex: number;
  treeSize:   number;
  origin:     string;
  schemaId:   number;
  issuedAt:   number;
  expiresAt:  number;
  claims:     Claims;
}

export interface VerifyFail {
  valid:       false;
  failedStep:  string;
  reason:      string;
}

export type VerifyResult = VerifyOk | VerifyFail;

export interface VerifyStep {
  name:   string;
  ok:     boolean;
  detail: string;
}

export interface VerifyTrace extends VerifyOk {
  steps: VerifyStep[];
}

export interface VerifyTraceResult {
  result: VerifyResult;
  steps:  VerifyStep[];
}

// --- Checkpoint cache ---

interface CachedCheckpoint {
  rootHash:  Uint8Array;
  fetchedAt: number;
}

// BATCH_SIZE is read from trust.batchSize at verification time

export type NoteProvider = (url: string) => string | Promise<string>;

export class Verifier {
  private readonly trust: TrustConfig;
  private readonly noteProvider: NoteProvider | undefined;
  // Bounded cache: cap at MAX_CACHE_ENTRIES to prevent memory exhaustion
  // from payloads with rapidly incrementing tree_size values.
  private static readonly MAX_CACHE_ENTRIES = 1000;
  private readonly cache = new Map<string, CachedCheckpoint>();
  private readonly revocCache = new Map<string, { cascade: Cascade; treeSize: bigint }>();

  /**
   * @param trust       Trust configuration from the issuer.
   * @param noteProvider Optional: supply a checkpoint note directly (for testing
   *                    or offline use). If omitted, the verifier fetches the note
   *                    from `trust.checkpointUrl` via HTTP.
   */
  constructor(trust: TrustConfig, noteProvider?: NoteProvider) {
    this.trust        = trust;
    this.noteProvider = noteProvider;
  }

  /**
   * Verify a QR code payload.
   * Returns VerifyOk with claims on success, VerifyFail with reason on failure.
   */
  async verify(payload: Uint8Array): Promise<VerifyResult> {
    const { result } = await this.verifyWithTrace(payload);
    return result;
  }

  /**
   * Verify a QR code payload and return the full verification trace.
   * Use this for debugging or building verification UIs.
   */
  async verifyWithTrace(payload: Uint8Array): Promise<VerifyTraceResult> {
    const steps: VerifyStep[] = [];
    const add = (name: string, ok: boolean, detail: string) => steps.push({ name, ok, detail });
    const fail = (step: string, reason: string): VerifyTraceResult => {
      add(step, false, reason);
      return { result: { valid: false, failedStep: step, reason }, steps };
    };
    const ok = (result: VerifyOk): VerifyTraceResult => ({ result, steps });

    // 1. Decode payload.
    let p;
    try { p = decodePayload(payload); }
    catch (e) { return fail("decode payload", `malformed: ${e}`); }
    add("decode payload", true,
      `mode=${p.mode} sig_alg=${p.sigAlg} entry_index=${p.entryIndex} tree_size=${p.treeSize}`);

    // 2. Reject null entry (index 0 is reserved).
    if (p.entryIndex === BigInt(0)) {
      return fail("entry index", "entry_index=0 is reserved for null_entry");
    }
    add("entry index", true, `entry_index=${p.entryIndex} valid`);

    // 3. Origin ID matches trust config.
    if (p.originId !== this.trust.originId) {
      return fail("origin id",
        `payload origin_id 0x${p.originId.toString(16)} does not match trust config`);
    }
    add("origin id", true, `matches trust config: "${this.trust.origin}"`);

    // 4. Self-describing origin consistency.
    if (p.selfDescrib && p.origin && p.origin !== this.trust.origin) {
      return fail("origin consistency",
        `envelope origin "${p.origin}" != trust config "${this.trust.origin}"`);
    }
    if (p.selfDescrib) add("origin consistency", true, `envelope matches trust config`);

    // 5. Algorithm binding.
    if (p.sigAlg !== this.trust.sigAlg) {
      return fail("algorithm binding",
        `payload sig_alg=${p.sigAlg} but trust config requires ${this.trust.sigAlg}`);
    }
    add("algorithm binding", true, `sig_alg=${p.sigAlg} matches trust config`);

    // 6. Checkpoint resolution.
    const cacheKey = `${this.trust.origin}:${p.treeSize}`;
    let rootHash: Uint8Array;
    const cached = this.cache.get(cacheKey);
    if (cached) {
      const age = Math.floor((Date.now() - cached.fetchedAt) / 1000);
      add("checkpoint", true, `cache hit · tree_size=${p.treeSize} · age=${age}s`);
      rootHash = cached.rootHash;
    } else {
      add("checkpoint", false, `cache miss · fetching ${this.trust.checkpointUrl}`);
      let fetched: Uint8Array;
      let fetchedSize: bigint;
      try {
        [fetched, fetchedSize] = await this.fetchAndVerifyCheckpoint(p.treeSize);
      } catch (e) {
        return fail("checkpoint fetch", String(e));
      }
      add("checkpoint fetch", true,
        `issuer sig ✓ · ${this.trust.witnessQuorum}/${this.trust.witnessQuorum} witnesses ✓ · tree_size=${fetchedSize}`);
      rootHash = fetched;
      if (this.cache.size >= Verifier.MAX_CACHE_ENTRIES) {
        // Evict the oldest entry (Maps preserve insertion order).
        this.cache.delete(this.cache.keys().next().value!);
      }
      this.cache.set(cacheKey, { rootHash: fetched, fetchedAt: Date.now() });
    }

    // 7. Entry hash.
    const eHash = entryHash(p.tbs);
    add("entry hash", true, `SHA-256(0x00 || tbs) = ${Buffer.from(eHash).toString("hex").slice(0, 16)}…`);

    // 8. Merkle inclusion proof — behaviour depends on mode.
    if (p.mode === 2) {
      // Mode 2 (online): NO INCLUSION PROOF IS VERIFIED HERE.
      // The payload carries no proof hashes. In a real deployment the scanner
      // fetches proof tiles from a tile server and verifies inclusion at scan time.
      // This SDK has no tile server — it only validates entry_index < tree_size.
      // Do not treat a Mode 2 VerifyOk as proof of inclusion.
      if (p.entryIndex >= p.treeSize) {
        return fail("inclusion proof", `mode=2: entry_index=${p.entryIndex} >= tree_size=${p.treeSize}`);
      }
      add("inclusion proof", true,
        `mode=2 (online): entry_index=${p.entryIndex} < tree_size=${p.treeSize} · proof fetched at scan time`);
    } else {
      // Mode 1 (cached): two-phase tiled Merkle proof embedded in payload.
      const globalIdx  = Number(p.entryIndex);
      const batchSize  = this.trust.batchSize;
      const innerIdx   = globalIdx % batchSize;
      const batchIdx   = Math.floor(globalIdx / batchSize);
      const numBatches = Math.ceil(Number(p.treeSize) / batchSize);
      const batchStart = batchIdx * batchSize;
      const thisBatchSz = Math.min(batchSize, Number(p.treeSize) - batchStart);

      const innerProof = p.proofHashes.slice(0, p.innerProofCount);
      const outerProof = p.proofHashes.slice(p.innerProofCount);

      let batchRoot: Uint8Array;
      try {
        batchRoot = computeRootFromProof(eHash, innerIdx, thisBatchSz, innerProof);
      } catch (e) {
        return fail("inclusion proof", `phase A (inner) failed: ${e}`);
      }
      try {
        verifyInclusion(batchRoot, batchIdx, numBatches, outerProof, rootHash);
      } catch (e) {
        return fail("inclusion proof", `phase B (outer) failed: ${e}`);
      }
      add("inclusion proof", true,
        `phase A: ${innerProof.length} hashes → batch root ✓ · phase B: ${outerProof.length} hashes → parent root ✓`);
    }

    // 9. TBS entry type.
    if (p.tbs.length < 2) return fail("tbs decode", "TBS too short");
    if (p.tbs[0] !== ENTRY_TYPE_DATA) {
      return fail("tbs decode", `unrecognized entry_type 0x${p.tbs[0].toString(16)}`);
    }
    add("tbs decode", true, `entry_type=data_assertion`);

    // 10. CBOR decode.
    let entry;
    try { entry = decodeTbs(p.tbs.slice(1)); }
    catch (e) { return fail("cbor decode", `${e}`); }
    add("cbor decode", true, `schema_id=${entry.schemaId} issued=${entry.times[0]} expires=${entry.times[1]}`);

    // 10. Revocation check — SPEC.md §Revocation.
    const revocResult = await this.checkRevocation(p.entryIndex, p.treeSize, this.trust);
    if (revocResult.revoked) return fail("revocation", revocResult.reason);
    add("revocation", true, revocResult.reason);

    // 11. Expiry (10-minute grace period).
    const now   = Math.floor(Date.now() / 1000);
    const grace = 600;
    if (entry.times[1] + grace < now) {
      return fail("expiry", `expired: expiry=${entry.times[1]} now=${now}`);
    }
    add("expiry", true, `valid · ${entry.times[1] - now}s remaining`);

    add("complete", true, `all checks passed · entry_index=${p.entryIndex} · origin="${this.trust.origin}"`);

    return ok({
      valid:      true,
      mode:       p.mode,
      entryIndex: Number(p.entryIndex),
      treeSize:   Number(p.treeSize),
      origin:     this.trust.origin,
      schemaId:   entry.schemaId,
      issuedAt:   entry.times[0],
      expiresAt:  entry.times[1],
      claims:     entry.claims,
    });
  }

  private async fetchAndVerifyCheckpoint(
    requiredSize: bigint,
  ): Promise<[Uint8Array, bigint]> {
    let note: string;
    if (this.noteProvider) {
      note = await this.noteProvider(this.trust.checkpointUrl);
    } else {
      const res = await fetch(this.trust.checkpointUrl);
      note = await res.text();
    }
    return this.verifyNote(note, requiredSize);
  }

  private async verifyNote(
    note: string,
    requiredSize: bigint,
  ): Promise<[Uint8Array, bigint]> {
    const blankIdx = note.indexOf("\n\n");
    if (blankIdx < 0) throw new Error("note missing blank-line separator");

    const bodyText = note.slice(0, blankIdx);
    const body     = new TextEncoder().encode(bodyText + "\n");
    const rest     = note.slice(blankIdx + 2);

    const { origin, treeSize, rootHash } = parseCheckpointBody(body);
    if (origin !== this.trust.origin) {
      throw new Error(`origin mismatch: got "${origin}" want "${this.trust.origin}"`);
    }
    if (treeSize < requiredSize) {
      throw new Error(`tree_size ${treeSize} < required ${requiredSize}`);
    }

    const sigLines = rest.split("\n").filter(l => l.trim() !== "");

    // Verify issuer signature by key name prefix match.
    // Never dispatch by signature byte length — Ed25519 and ECDSA-P256 are
    // both 64 bytes, and ML-DSA-44 at 2420 bytes would break any length heuristic.
    let issuerOk = false;
    for (const line of sigLines) {
      if (!line.includes(this.trust.issuerKeyName)) continue;
      const raw = lastFieldBase64(line);
      if (!raw || raw.length < 4) continue;
      // Per c2sp.org/signed-note: first 4 bytes are the key hash; remaining bytes are the sig.
      const rawSig = raw.slice(4);
      if (verifySig(this.trust.sigAlg, body, rawSig, this.trust.issuerPubKey)) {
        issuerOk = true;
        break;
      }
    }
    if (!issuerOk) throw new Error("issuer signature not found or invalid");

    // Verify witness cosignatures. Witnesses always use Ed25519.
    const verified = new Set<string>();
    for (const line of sigLines) {
      const raw = lastFieldBase64(line);
      // Per c2sp.org/signed-note + tlog-cosignature: 4-byte key_hash || 8-byte ts || 64-byte sig
      if (!raw || raw.length !== 76) continue;
      const keyHash = raw.slice(0, 4);
      const tsBuf   = raw.slice(4, 12);
      const ts      = tsBuf.reduce(
        (acc, b, i) => acc | (BigInt(b) << BigInt((7 - i) * 8)), BigInt(0)
      );
      const sig     = raw.slice(12, 76);
      for (const w of this.trust.witnesses) {
        if (!keyHash.every((b, i) => b === w.keyId[i])) continue;
        if (verifySig(SIG_ALG_ED25519, cosignatureMessage(body, ts), sig, w.pubKey)) {
          verified.add(w.name);
        }
      }
    }
    if (verified.size < this.trust.witnessQuorum) {
      throw new Error(`witness quorum not met: ${verified.size}/${this.trust.witnessQuorum}`);
    }

    return [rootHash, treeSize];
  }

  /** Revocation check — SPEC.md §Revocation — Verifier Behavior. */
  private async checkRevocation(
    entryIndex: bigint, checkpointTreeSize: bigint, trust: TrustConfig
  ): Promise<{ revoked: boolean; reason: string }> {
    const STALE = 32n; // 2 × BATCH_SIZE
    if (!trust.revocationUrl)
      return { revoked: false, reason: "skipped — no revocation_url (fail-open)" };

    let cached = this.revocCache.get(trust.origin) ?? null;
    if (cached && checkpointTreeSize > cached.treeSize &&
        checkpointTreeSize - cached.treeSize > STALE) cached = null;

    if (!cached) {
      let raw: string;
      try {
        if (typeof fetch === "function") {
          const r = await fetch(trust.revocationUrl);
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          raw = await r.text();
        } else {
          const http = await import("http");
          raw = await new Promise((res, rej) =>
            http.get(trust.revocationUrl, r => {
              const c: Buffer[] = [];
              r.on("data", (d: Buffer) => c.push(d));
              r.on("end", () => res(Buffer.concat(c).toString("utf8")));
              r.on("error", rej);
            }).on("error", rej));
        }
      } catch (e) {
        return { revoked: true, reason: `no artifact (fail-closed): ${e}` };
      }
      const p = this.parseRevArtifact(raw, trust);
      if ("error" in p) return { revoked: true, reason: `bad artifact (fail-closed): ${p.error}` };
      this.revocCache.set(trust.origin, p);
      cached = p;
    }

    if (cached.treeSize <= entryIndex)
      return { revoked: true, reason: `entry ${entryIndex} not covered by artifact (tree_size=${cached.treeSize}) — fail-closed` };
    if (cached.cascade.query(entryIndex))
      return { revoked: true, reason: `entry_index=${entryIndex} is revoked` };
    return { revoked: false, reason: `not revoked (cascade, artifact tree_size=${cached.treeSize})` };
  }

  private parseRevArtifact(
    text: string, trust: TrustConfig
  ): { cascade: Cascade; treeSize: bigint } | { error: string } {
    const parts = text.split("\n\n");
    if (parts.length < 2) return { error: "missing blank line" };
    const bodyLines = parts[0].split("\n");
    if (bodyLines.length !== 4) return { error: `expected 4 body lines, got ${bodyLines.length}` };
    const [origin, treeSizeStr, artifactType, cascB64] = bodyLines;
    if (origin !== trust.origin) return { error: `origin mismatch: ${origin}` };
    if (artifactType !== "mta-qr-revocation-v1") return { error: `unknown type: ${artifactType}` };
    const treeSize = BigInt(treeSizeStr);
    if (treeSize === 0n) return { error: "tree_size=0" };
    let cascBytes: Uint8Array;
    try { cascBytes = Uint8Array.from(Buffer.from(cascB64, "base64")); }
    catch { return { error: "base64 failed" }; }
    let cascade: Cascade;
    try { cascade = Cascade.decode(cascBytes); }
    catch (e) { return { error: `cascade decode: ${e}` }; }
    // Verify signature — algorithm binding per SPEC.md.
    const body = parts[0] + "\n";
    const sigBlock = parts.slice(1).join("\n\n").trim();
    const prefix = `\u2014 ${trust.issuerKeyName} `;
    const sigLine = sigBlock.split("\n").find(l => l.startsWith(prefix));
    if (!sigLine) return { error: "issuer sig line not found" };
    const sigRaw = Buffer.from(sigLine.slice(prefix.length), "base64");
    if (sigRaw.length < 4) return { error: "sig line too short" };
    const pub = trust.issuerPubKey;
    if (!verifySig(trust.sigAlg, new TextEncoder().encode(body), sigRaw.subarray(4), pub))
      return { error: "signature verification failed" };
    return { cascade, treeSize };
  }
}

function lastFieldBase64(line: string): Uint8Array | null {
  const idx = line.lastIndexOf(" ");
  if (idx < 0) return null;
  try {
    return new Uint8Array(Buffer.from(line.slice(idx + 1).trim(), "base64"));
  } catch { return null; }
}
