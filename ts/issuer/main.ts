/**
 * MTA-QR TypeScript Issuer
 * Mode 1 · Port configurable via MTA_PORT (default 3001)
 */
import { createServer, IncomingMessage, ServerResponse } from "http";
import { randomBytes, createHash } from "crypto";
import QRCode from "qrcode";

import { encodeNullTbs as encodeNullEntry, encodeTbs as encodeDataAssertion, decodeTbs as decodeDataAssertion } from "../sdk/src/cbor.js";
import { entryHash, inclusionProof, computeRoot } from "../sdk/src/merkle.js";
import {
  checkpointBody, signCheckpointBody as signCheckpoint, signCosignature,
  noteKeyId as witnessKeyID, computeOriginId as computeOriginID, pubKeyFromSeed, generateSeed
} from "../sdk/src/checkpoint.js";
import { ed25519FromSeed, ecdsaP256FromScalar, mlDsa44FromSeed, newEd25519, newECDSAP256, newMLDSA44, SIG_ALG_ED25519, SIG_ALG_ECDSA_P256, SIG_ALG_MLDSA44, sigAlgName } from "../sdk/src/signers/local.js";
import type { LocalSigner } from "../sdk/src/signer.js";
import { encodePayload, MODE_EMBEDDED, MODE_CACHED, WitnessCosig } from "../sdk/src/payload.js";
import { Cascade } from "../sdk/src/cascade.js";

const ORIGIN = process.env.MTA_ORIGIN ?? "demo.mta-qr.example/ts-issuer/v1";
const PORT   = parseInt(process.env.MTA_PORT ?? "3001", 10);

// --- Key material ---
// Instantiate issuer Signer from MTA_SIG_ALG env (default Ed25519).
function makeIssuerSigner(): LocalSigner {
  const alg = process.env.MTA_SIG_ALG ?? "";
  if (alg === "ecdsa-p256" || alg === "4") {
    const scalar = new Uint8Array(createHash("sha256").update("ts-issuer-ecdsa-scalar").digest());
    return ecdsaP256FromScalar(scalar);
  }
  if (alg === "mldsa44" || alg === "ml-dsa-44" || alg === "1") {
    const seed = new Uint8Array(createHash("sha256").update("ts-issuer-mldsa44-seed").digest());
    return mlDsa44FromSeed(seed);
  }
  return ed25519FromSeed(generateSeed());
}
const issuerSigner: LocalSigner = makeIssuerSigner();
const issuerPub = issuerSigner.publicKeyBytes();
// Per c2sp.org/signed-note: key_id = SHA-256(name||0x0A||0x01||pub)[0:4]
const issuerKeyID = witnessKeyID(issuerSigner.keyName, issuerPub);

interface WitnessKey { name: string; keyId: Uint8Array; pub: Uint8Array; seed: Uint8Array; }
const witnesses: WitnessKey[] = [0, 1].map(i => {
  const seed = generateSeed();
  const pub  = pubKeyFromSeed(seed);
  const name = `ts-witness-${i}`;
  return { name, keyId: witnessKeyID(name, pub), pub, seed };
});

const originId = computeOriginID(ORIGIN);

// --- Log state ---
interface LogEntry { index: number; tbs: Uint8Array; hash: Uint8Array; }
interface SignedCheckpoint {
  treeSize: number; rootHash: Uint8Array; body: Uint8Array;
  issuerSig: Uint8Array; cosigs: WitnessCosig[];
}

// ── Tiled batch tree constants (must match Go log.BatchSize / log.OuterMaxBatches) ──
const BATCH_SIZE       = 16;
const OUTER_MAX_BATCHES = 16;

interface Batch { entries: LogEntry[]; root: Uint8Array; }

// ── Log state ──────────────────────────────────────────────────────────────
const batches:      Batch[] = [];   // completed batches
let   currentBatch: LogEntry[] = []; // in-progress batch
let   latestCkpt:        SignedCheckpoint | null = null;
const revokedIndices   = new Set<bigint>();
let   latestRevArtifact: string | null = null;

function totalEntries(): number {
  return batches.reduce((n, b) => n + b.entries.length, 0) + currentBatch.length;
}

function batchRoots(): Uint8Array[] {
  const roots = batches.map(b => b.root);
  if (currentBatch.length > 0) {
    roots.push(computeRoot(currentBatch.map(e => e.hash)));
  }
  return roots;
}

function appendEntry(tbs: Uint8Array): number {
  const idx = totalEntries();
  currentBatch.push({ index: idx, tbs, hash: entryHash(tbs) });
  // Finalise batch when full
  if (currentBatch.length >= BATCH_SIZE) {
    const batchRoot = computeRoot(currentBatch.map(e => e.hash));
    batches.push({ entries: currentBatch, root: batchRoot });
    currentBatch = [];
    // Roll outer tree when it reaches OuterMaxBatches
    if (batches.length >= OUTER_MAX_BATCHES) {
      batches.length = 0;
      const nullTbs = encodeNullEntry();
      currentBatch = [{ index: 0, tbs: nullTbs, hash: entryHash(nullTbs) }];
    }
  }
  return idx;
}

function publishCheckpoint(): SignedCheckpoint {
  const parentRoot = computeRoot(batchRoots());
  const treeSize   = totalEntries();
  const body       = checkpointBody(ORIGIN, BigInt(treeSize), parentRoot);
  const isig       = issuerSigner.sign(body);
  const ts         = BigInt(Math.floor(Date.now() / 1000));
  const cosigs: WitnessCosig[] = witnesses.map(w => {
    const sig = signCosignature(body, ts, w.seed);
    const s64 = new Uint8Array(64); s64.set(sig);
    return { keyId: w.keyId, timestamp: ts, signature: s64 };
  });
  latestCkpt = { treeSize, rootHash: parentRoot, body, issuerSig: isig, cosigs };
  latestRevArtifact = buildRevocationArtifact(treeSize);
  return latestCkpt;
}

function buildRevocationArtifact(treeSize: number): string {
  // Build R (revoked) and S (valid non-revoked, non-expired).
  // Index 0 (null entry) is always excluded per SPEC.md §Revocation.
  const now = BigInt(Math.floor(Date.now() / 1000));
  const revoked: bigint[] = [];
  const valid:   bigint[] = [];

  const allBatchEntries = [
    ...batches.flatMap(b => b.entries),
    ...currentBatch,
  ];
  for (const e of allBatchEntries) {
    if (e.index === 0) continue;
    const idx = BigInt(e.index);
    if (revokedIndices.has(idx)) { revoked.push(idx); continue; }
    // Exclude expired entries — decode expiry_time from TBS CBOR field 2.
    const exp = entryExpiryTime(e.tbs);
    if (exp > 0n && exp < now) continue;
    valid.push(idx);
  }

  const casc = Cascade.build(revoked, valid);
  const cascBytes = casc.encode();
  const cascB64 = Buffer.from(cascBytes).toString("base64");
  const body = `${ORIGIN}\n${treeSize}\nmta-qr-revocation-v1\n${cascB64}\n`;

  // Sign with issuer key — same key as checkpoints.
  const sig = issuerSigner.sign(new TextEncoder().encode(body));
  const keyId = issuerKeyId();
  const sigBytes = new Uint8Array(4 + sig.length);
  sigBytes.set(keyId, 0);
  sigBytes.set(sig, 4);
  const sigLine = `\n\u2014 ${issuerSigner.keyName} ${Buffer.from(sigBytes).toString("base64")}\n`;
  return body + sigLine;
}

function issuerKeyId(): Uint8Array {
  // 4-byte key hash per c2sp.org/signed-note: SHA-256(name || 0x0A || 0x01 || pubkey)[0:4]
  const name = issuerSigner.keyName;
  const pub  = issuerSigner.publicKeyBytes();
  const buf  = new Uint8Array(name.length + 1 + 1 + pub.length);
  new TextEncoder().encodeInto(name, buf);
  buf[name.length]     = 0x0a;
  buf[name.length + 1] = 0x01;
  buf.set(pub, name.length + 2);
  const h = createHash("sha256").update(buf).digest();
  return h.subarray(0, 4);
}

function entryExpiryTime(tbs: Uint8Array): bigint {
  // TBS[0] is entry_type_byte; 0x01 = data assertion.
  // CBOR map key 2 → [issuance_time, expiry_time].
  if (tbs.length < 2 || tbs[0] !== 0x01) return 0n;
  try {
    const decoded = decodeDataAssertion(tbs);
    return BigInt(decoded.times[1]);
  } catch { return 0n; }
}

function buildMode1Payload(entryIdx: number, tbs: Uint8Array): Uint8Array {
  const ckpt = latestCkpt!;

  // Locate which batch this entry belongs to.
  const batchIdx = Math.floor(entryIdx / BATCH_SIZE);
  const innerIdx = entryIdx % BATCH_SIZE;

  let batchEntryHashes: Uint8Array[];
  let batchSz: number;
  if (batchIdx < batches.length) {
    batchEntryHashes = batches[batchIdx].entries.map(e => e.hash);
    batchSz = batches[batchIdx].entries.length;
  } else {
    batchEntryHashes = currentBatch.map(e => e.hash);
    batchSz = currentBatch.length;
  }

  // Inner proof: entry → batch root.
  const innerProof = inclusionProof(batchEntryHashes, innerIdx, batchSz);

  // Outer proof: batch root → parent tree root.
  const allBatchRoots = batchRoots();
  const outerProof    = inclusionProof(allBatchRoots, batchIdx, allBatchRoots.length);

  return encodePayload({
    version: 0x01, mode: MODE_CACHED, sigAlg: issuerSigner.sigAlg,
    dualSig: false, selfDescrib: true,
    originId: originId, treeSize: BigInt(ckpt.treeSize),
    entryIndex: BigInt(entryIdx),
    origin: ORIGIN,
    proofHashes:     [...innerProof, ...outerProof],
    innerProofCount: innerProof.length,
    tbs,
  });
}

// Init: null_entry at index 0, initial checkpoint.
appendEntry(encodeNullEntry());
publishCheckpoint();
console.log(`TS issuer started on :${PORT}`);
console.log(`Origin: ${ORIGIN}`);
console.log(`Issuer pub: ${Buffer.from(issuerPub).toString("hex")}`);

// --- HTTP server ---
function setCORS(res: ServerResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

const MAX_BODY = 64 * 1024;
async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c: string) => {
      body += c;
      if (body.length > MAX_BODY) { req.destroy(); reject(new Error("request body too large")); }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function json(res: ServerResponse, data: unknown, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function text(res: ServerResponse, data: string, ct = "text/plain") {
  res.writeHead(200, { "Content-Type": ct });
  res.end(data);
}

const server = createServer(async (req, res) => {
  setCORS(res);
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url!, `http://localhost:${PORT}`);

  // GET /checkpoint — tlog-checkpoint signed note
  if (req.method === "GET" && url.pathname === "/checkpoint") {
    const ckpt = latestCkpt!;
    let note = Buffer.from(ckpt.body).toString() + "\n";
    // Per c2sp.org/signed-note: payload = 4-byte key_hash || raw_sig
    const issuerPayload = new Uint8Array(4 + ckpt.issuerSig.length);
    issuerPayload.set(issuerKeyID, 0);
    issuerPayload.set(ckpt.issuerSig, 4);
    note += `— ${issuerSigner.keyName} ${Buffer.from(issuerPayload).toString("base64")}\n`;
    for (let i = 0; i < witnesses.length; i++) {
      const w = witnesses[i];
      const c = ckpt.cosigs[i];
      // Per c2sp.org/signed-note + tlog-cosignature:
      //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes
      const payload = new Uint8Array(76);
      payload.set(w.keyId, 0);
      let tsVal = c.timestamp;
      for (let j = 7; j >= 0; j--) { payload[4 + j] = Number(tsVal & BigInt(0xff)); tsVal >>= BigInt(8); }
      payload.set(c.signature, 12);
      note += `— ${w.name} ${Buffer.from(payload).toString("base64")}\n`;
    }
    return text(res, note);
  }

  // GET /revoked — signed revocation artifact
  if (req.method === "GET" && url.pathname === "/revoked") {
    if (!latestRevArtifact) {
      res.writeHead(503); res.end("no revocation artifact available"); return;
    }
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8",
                          "Access-Control-Allow-Origin": "*" });
    res.end(latestRevArtifact);
    return;
  }

  // POST /revoke — demo endpoint to revoke an entry by index
  if (req.method === "POST" && url.pathname === "/revoke") {
    let body: { entry_index?: number };
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, { error: "bad JSON" }, 400); }
    const idx = BigInt(body.entry_index ?? -1);
    if (idx <= 0n) return json(res, { error: "entry_index must be > 0" }, 400);
    if (idx >= BigInt(totalEntries())) return json(res, { error: "entry_index not yet issued" }, 400);
    revokedIndices.add(idx);
    latestRevArtifact = buildRevocationArtifact(totalEntries());
    return json(res, { revoked: true });
  }

  // GET /trust-config
  if (req.method === "GET" && url.pathname === "/trust-config") {
    const baseURL = (process.env.MTA_BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, "");
    return json(res, {
      origin:             ORIGIN,
      origin_id:          originId.toString(16).padStart(16, "0"),
      issuer_pub_key_hex: Buffer.from(issuerPub).toString("hex"),
      issuer_key_name:    issuerSigner.keyName,
      sig_alg:            issuerSigner.sigAlg,
      witness_quorum:     witnesses.length,
      checkpoint_url:     `${baseURL}/checkpoint`,
      revocation_url:    `${baseURL}/revoked`,
      batch_size:         BATCH_SIZE,
      witnesses: witnesses.map(w => ({
        name:        w.name,
        key_id_hex:  Buffer.from(w.keyId).toString("hex"),
        pub_key_hex: Buffer.from(w.pub).toString("hex"),
      })),
    });
  }

function buildMode0Payload(entryIdx: number, tbs: Uint8Array): Uint8Array {
  const ckpt = latestCkpt!;
  // Build the two-phase tiled inclusion proof (same pattern as buildMode1Payload).
  const batchIdx = Math.floor(entryIdx / BATCH_SIZE);
  const innerIdx = entryIdx % BATCH_SIZE;
  let batchEntryHashes: Uint8Array[];
  let batchSz: number;
  if (batchIdx < batches.length) {
    batchEntryHashes = batches[batchIdx].entries.map(e => e.hash);
    batchSz = batches[batchIdx].entries.length;
  } else {
    batchEntryHashes = currentBatch.map(e => e.hash);
    batchSz = currentBatch.length;
  }
  const innerProof = inclusionProof(batchEntryHashes, innerIdx, batchSz);
  const allRoots = batchRoots();
  const outerProof = inclusionProof(allRoots, batchIdx, allRoots.length);
  const allProof = [...innerProof, ...outerProof];

  // Use the issuer sig from the stored checkpoint — it was signed at publishCheckpoint time.
  // latestCkpt.issuerSig is the raw sig bytes (no signed-note prefix).
  const body = ckpt.body;  // canonical body already computed at checkpoint time
  const issuerSig = ckpt.issuerSig;

  // Witness cosignatures.
  const cosigs: WitnessCosig[] = witnesses.map(w => {
    const ts = BigInt(Math.floor(Date.now() / 1000));
    const sig = signCosignature(body, ts, w.seed);
    return { keyId: w.keyId, timestamp: ts, signature: sig };
  });

  return encodePayload({
    version: 0x01, mode: MODE_EMBEDDED, sigAlg: issuerSigner.sigAlg,
    dualSig: false, selfDescrib: true,
    originId, treeSize: BigInt(ckpt.treeSize), entryIndex: BigInt(entryIdx), origin: ORIGIN,
    proofHashes: allProof, innerProofCount: innerProof.length,
    tbs,
    rootHash: ckpt.rootHash, issuerSig, cosigs,
  });
}

  // POST /issue
  if (req.method === "POST" && url.pathname === "/issue") {
    let body: { schema_id?: number; ttl_seconds?: number; claims?: Record<string, unknown> };
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, { error: "bad JSON" }, 400); }

    const ttl      = (body as any).ttl_seconds ?? 3600;
    const schemaId = (body as any).schema_id ?? 1;
    const claims   = (body as any).claims ?? {};
    const mode     = (body as any).mode ?? 1;
    const now    = Math.floor(Date.now() / 1000);
    const expiry = now + ttl;

    const tbs    = encodeDataAssertion({ times: [now, expiry], schemaId, claims });
    const idx    = appendEntry(tbs);
    publishCheckpoint();
    const payloadBytes = mode === 0 ? buildMode0Payload(idx, tbs) : buildMode1Payload(idx, tbs);
    const payloadHex   = Buffer.from(payloadBytes).toString("hex");
    const payloadB64   = Buffer.from(payloadBytes).toString("base64");
    const payloadB64Url = Buffer.from(payloadBytes).toString("base64url");

    return json(res, {
      entry_index:  idx,
      tree_size:    latestCkpt!.treeSize,
      payload_hex:  payloadHex,
      payload_b64:  payloadB64,
      qr_png_url:   `/qr.png?payload=${payloadB64Url}`,
    });
  }

  // GET /qr.png?payload=<base64url>
  if (req.method === "GET" && url.pathname === "/qr.png") {
    const payloadParam = url.searchParams.get("payload");
    if (!payloadParam) { res.writeHead(400); res.end("missing payload"); return; }
    const payloadBytes = Buffer.from(payloadParam, "base64url");
    try {
      const png = await QRCode.toBuffer(payloadBytes.toString("binary"), {
        errorCorrectionLevel: "M",
        type: "png",
        width: 400,
      });
      res.writeHead(200, { "Content-Type": "image/png" });
      res.end(png);
    } catch (e) {
      json(res, { error: String(e) }, 500);
    }
    return;
  }

  // GET / — web UI
  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
    const algName = sigAlgName(issuerSigner.sigAlg);
    return text(res, issuerHTML
      .replace("__IMPL__", "TypeScript")
      .replace(/__ALG__/g, algName)
      .replace("__PORT__", String(PORT))
      .replace("__VERIFIER_PORT__", "3002")
      .replace("__GO_VERIFIER_PORT__", "8082"), "text/html");
  }

  res.writeHead(404); res.end("not found");
});

server.listen(PORT);

// --- Web UI (same structure as Go issuer, different colors) ---
const issuerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MTA-QR __IMPL__ Issuer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; }
  .badge.ts  { background: #3178c622; color: #3178c6; border: 1px solid #3178c644; }
  .badge.info { background: #388bfd22; color: #388bfd; border: 1px solid #388bfd44; }
  main { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { padding: 24px; border-right: 1px solid #30363d; overflow-y: auto; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #8b949e; margin-bottom: 20px; }
  .field { margin-bottom: 16px; }
  label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 6px; }
  input, textarea { width: 100%; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 13px; }
  input:focus, textarea:focus { outline: none; border-color: #3178c6; }
  button { background: #1a6b3c; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-family: inherit; font-size: 13px; cursor: pointer; width: 100%; font-weight: 600; }
  button:hover { background: #238636; }
  .result { display: none; margin-top: 24px; }
  .result.show { display: block; }
  .qr-wrap { text-align: center; margin-bottom: 20px; }
  .qr-wrap img { border: 4px solid #fff; border-radius: 4px; max-width: 280px; }
  .info-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 12px; font-size: 12px; }
  .kv { display: flex; gap: 8px; margin-bottom: 4px; }
  .k { color: #8b949e; flex-shrink: 0; } .v { color: #58a6ff; word-break: break-all; }
  .hex-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: 11px; color: #7ee787; word-break: break-all; max-height: 120px; overflow-y: auto; }
  .status { padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-bottom: 12px; }
  .status.ok { background: #1f3d1f; color: #56d364; border: 1px solid #2ea04344; }
  .status.err { background: #3d1f1f; color: #f85149; border: 1px solid #f8514944; }
  .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 8px; }
  .example-btn { background: #161b22; border: 1px solid #30363d; color: #8b949e; padding: 8px 12px; border-radius: 6px; cursor: pointer; text-align: left; font-size: 12px; width: 100%; margin-bottom: 6px; }
  .example-btn:hover { border-color: #3178c6; color: #3178c6; }
</style>
</head>
<body>
<header>
  <h1>MTA-QR Demo</h1>
  <span class="badge ts">__IMPL__ Issuer</span>
  <span class="badge info">__ALG__ · Mode 1</span>
  <span class="badge info" id="entry-count">1 entry</span>
</header>
<main>
  <div class="panel">
    <h2>Examples</h2>
    <button class="example-btn" onclick="loadEx('ticket')">🎫 Event Ticket</button>
    <button class="example-btn" onclick="loadEx('prescription')">💊 Prescription</button>
    <button class="example-btn" onclick="loadEx('badge')">🪪 Access Badge</button>
    <button class="example-btn" onclick="loadEx('package')">📦 Package Label</button>
    <button class="example-btn" onclick="loadEx('membership')">🔄 Rotating Membership</button>

    <h2 style="margin-top:20px">Issue Assertion</h2>
    <div class="field">
      <label>Schema ID</label>
      <input type="number" id="schema-id" value="1">
    </div>
    <div class="field">
      <label>TTL (seconds)</label>
      <input type="number" id="ttl" value="3600">
    </div>
    <div class="field">
      <label>Claims</label>
      <div id="claims-fields">
        <div class="field-row"><input type="text" placeholder="key" class="ck"><input type="text" placeholder="value" class="cv"></div>
      </div>
      <button type="button" onclick="addField()" style="background:#21262d;color:#8b949e;width:auto;padding:6px 12px;margin-top:4px">+ Add field</button>
    </div>
    <button id="btn" onclick="issue()">Issue QR Code</button>

    <div style="margin-top:16px;font-size:12px;color:#8b949e">
      <div>Origin: <span style="color:#c9d1d9" id="log-origin">loading...</span></div>
      <div>Entries: <span style="color:#c9d1d9" id="log-entries">-</span></div>
    </div>
  </div>

  <div class="panel">
    <h2>Result</h2>
    <div id="status"></div>
    <div class="result" id="result">
      <div class="qr-wrap"><img id="qr-img" src="" alt="QR Code"></div>
      <div class="info-block">
        <div class="kv"><span class="k">Entry index:</span><span class="v" id="r-idx">-</span></div>
        <div class="kv"><span class="k">Tree size:</span><span class="v" id="r-tree">-</span></div>
        <div class="kv"><span class="k">Issuer:</span><span class="v">__IMPL__ (__ALG__)</span></div>
      </div>
      <h2 style="margin-bottom:8px">Payload hex</h2>
      <div class="hex-block" id="r-hex"></div>
      <h2 style="margin-top:16px;margin-bottom:8px">Verify with</h2>
      <div style="display:flex;gap:8px">
        <button onclick="openV(__VERIFIER_PORT__)" style="background:#21262d;color:#8b949e;border:1px solid #30363d;width:auto;padding:8px 16px">TS Verifier :__VERIFIER_PORT__</button>
        <button onclick="openV(__GO_VERIFIER_PORT__)" style="background:#21262d;color:#8b949e;border:1px solid #30363d;width:auto;padding:8px 16px">Go Verifier :__GO_VERIFIER_PORT__</button>
      </div>
    </div>

    <div style="margin-top:24px">
      <h2 style="margin-bottom:12px">Current Checkpoint</h2>
      <div class="hex-block" id="ckpt-display" style="color:#c9d1d9;white-space:pre-wrap;max-height:200px"></div>
    </div>
  </div>
</main>
<script>
let lastB64='';
const examples={
  ticket:{schema_id:1001,ttl_seconds:86400,claims:{event:'MTA-QR Summit 2026',seat:'B-42',tier:'general'}},
  prescription:{schema_id:1002,ttl_seconds:604800,claims:{drug:'Amoxicillin 500mg',qty:'20',prescriber:'Dr. Smith'}},
  badge:{schema_id:1003,ttl_seconds:28800,claims:{holder:'A. Example',zones:'A,B,C'}},
  package:{schema_id:1004,ttl_seconds:2592000,claims:{sku:'PKG-00441',batch:'2026-Q1-B'}},
  membership:{schema_id:1005,ttl_seconds:300,claims:{member_id:'M-'+Math.floor(Math.random()*99999),tier:'premium'}},
};
function loadEx(n){
  const e=examples[n];
  document.getElementById('schema-id').value=e.schema_id;
  document.getElementById('ttl').value=e.ttl_seconds;
  const cf=document.getElementById('claims-fields');
  cf.innerHTML='';
  for(const[k,v] of Object.entries(e.claims)) addField(k,String(v));
}
function addField(k='',v=''){
  const r=document.createElement('div');
  r.className='field-row';
  r.innerHTML='<input type="text" placeholder="key" class="ck" value="'+k+'"><input type="text" placeholder="value" class="cv" value="'+v+'">';
  document.getElementById('claims-fields').appendChild(r);
}
async function issue(){
  const btn=document.getElementById('btn');
  btn.disabled=true; btn.textContent='Issuing...';
  document.getElementById('status').innerHTML='';
  const claims={};
  document.querySelectorAll('.ck').forEach((k,i)=>{
    const ks=document.querySelectorAll('.ck'), vs=document.querySelectorAll('.cv');
    if(ks[i].value.trim()) claims[ks[i].value.trim()]=vs[i].value.trim();
  });
  const body={schema_id:+document.getElementById('schema-id').value,ttl_seconds:+document.getElementById('ttl').value,claims};
  try{
    const r=await fetch('/issue',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok){const el=document.getElementById('status')!;const div=document.createElement('div');div.className='status err';div.textContent=JSON.stringify(d);el.replaceChildren(div);btn.disabled=false;btn.textContent='Issue QR Code';return;}
    lastB64=d.payload_b64;
    document.getElementById('qr-img').src=d.qr_png_url;
    document.getElementById('r-idx').textContent=d.entry_index;
    document.getElementById('r-tree').textContent=d.tree_size;
    document.getElementById('r-hex').textContent=d.payload_hex;
    document.getElementById('result').classList.add('show');
    document.getElementById('status').innerHTML='<div class="status ok">Issued at index '+d.entry_index+'</div>';
    refresh();
  }catch(e){const el=document.getElementById('status')!;const div=document.createElement('div');div.className='status err';div.textContent=String((e as Error).message);el.replaceChildren(div);}
  btn.disabled=false; btn.textContent='Issue QR Code';
}
function openV(port){window.open('http://localhost:'+port+'/?payload='+encodeURIComponent(lastB64),'_blank');}
async function refresh(){
  try{
    const tc=await(await fetch('/trust-config')).json();
    document.getElementById('log-origin').textContent=tc.origin;
    const ckpt=await(await fetch('/checkpoint')).text();
    document.getElementById('ckpt-display').textContent=ckpt;
    document.getElementById('log-entries').textContent=ckpt.split('\\n')[1]||'-';
    document.getElementById('entry-count').textContent=(ckpt.split('\\n')[1]||'1')+' entries';
  }catch{}
}
addField('subject','demo'); addField('note','MTA-QR TS prototype');
refresh(); setInterval(refresh,5000);
</script>
</body>
</html>`;
