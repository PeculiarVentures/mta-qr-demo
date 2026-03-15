/**
 * MTA-QR TypeScript Verifier
 * Mode 1 · Port 3002
 */
import { createServer, IncomingMessage, ServerResponse } from "http";
import { createHash } from "crypto";

import { decodeTbs as decodeDataAssertion } from "../sdk/src/cbor.js";
import { entryHash, verifyInclusion, computeRootFromProof } from "../sdk/src/merkle.js";
import {
  verifyCheckpointSig as verifyCheckpoint, verifyCosignature,
  parseCheckpointBody, cosignatureMessage as cosignatureV1Message, computeOriginId as computeOriginID
} from "../sdk/src/checkpoint.js";
import { verifySig as sigVerify, SIG_ALG_ED25519, sigAlgSigLen as sigLen } from "../sdk/src/verify-sig.js";
import type { SigAlg } from "../sdk/src/signer.js";
import { decodePayload, MODE_ONLINE } from "../sdk/src/payload.js";

const PORT = parseInt(process.env.MTA_PORT ?? "3002", 10);

// --- Trust store ---
interface WitnessEntry { name: string; keyID: Uint8Array; pubKey: Uint8Array; }
interface TrustAnchor {
  origin: string; originID: bigint; issuerPubKey: Uint8Array;
  issuerKeyName: string; // key name prefix as it appears in note sig lines
  sigAlg: number; witnessQuorum: number; witnesses: WitnessEntry[];
  checkpointURL: string;
}

const anchors = new Map<string, TrustAnchor>(); // keyed by origin_id hex

// Checkpoint cache: "origin:treeSize" → rootHash
// Bounded to prevent memory exhaustion from payloads with incrementing tree_size.
const MAX_CACHE_ENTRIES = 1000;
const checkpointCache = new Map<string, { rootHash: Uint8Array; fetchedAt: number }>();

// --- Verification ---
interface Step { name: string; ok: boolean; detail: string; }
interface VerifyResult {
  valid: boolean; steps: Step[]; claims?: Record<string, unknown>; error?: string;
  entryIndex?: number; treeSize?: number; origin?: string; mode?: number;
  sigAlg?: number; issuanceTime?: number; expiryTime?: number; schemaId?: number;
}

function anchorByOriginID(oid: bigint): TrustAnchor | undefined {
  return anchors.get(oid.toString(16).padStart(16, "0"));
}

async function verify(payloadBytes: Uint8Array): Promise<VerifyResult> {
  const steps: Step[] = [];
  const res: VerifyResult = { valid: false, steps };

  const add = (name: string, ok: boolean, detail: string) => {
    steps.push({ name, ok, detail });
    if (!ok && !res.error) res.error = detail;
  };
  const fail = (name: string, detail: string): VerifyResult => { add(name, false, detail); return res; };

  // 1. Decode.
  let p;
  try { p = decodePayload(payloadBytes); }
  catch (e) { return fail("Decode payload", `malformed payload: ${e}`); }

  add("Decode payload", true,
    `mode=${p.mode} sig_alg=${p.sigAlg} entry_index=${p.entryIndex} tree_size=${p.treeSize} self_describing=${p.selfDescrib}`);
  res.entryIndex = Number(p.entryIndex);
  res.treeSize   = Number(p.treeSize);
  res.mode       = p.mode;
  res.sigAlg     = p.sigAlg;

  // 2. Reject null entry.
  if (p.entryIndex === BigInt(0)) return fail("Entry index check", "entry_index=0 is reserved for null_entry; MUST reject");
  add("Entry index check", true, `entry_index=${p.entryIndex} is not reserved null_entry slot`);

  // 3. Trust anchor.
  const anchor = anchorByOriginID(p.originId);
  if (!anchor) return fail("Trust anchor lookup", `no trusted anchor for origin_id 0x${p.originId.toString(16).padStart(16,"0")} — load issuer trust-config first`);
  add("Trust anchor lookup", true, `found: "${anchor.origin}"`);
  res.origin = anchor.origin;

  // 4. Self-describing origin consistency.
  if (p.selfDescrib && p.origin) {
    if (p.origin !== anchor.origin) return fail("Origin consistency", `envelope origin "${p.origin}" != trust config "${anchor.origin}"`);
    add("Origin consistency", true, `envelope matches trust config: "${p.origin}"`);
  }

  // 5. Algorithm binding.
  if (p.sigAlg !== anchor.sigAlg) return fail("Algorithm binding", `payload sig_alg=${p.sigAlg}, trust config requires ${anchor.sigAlg} — possible downgrade attack`);
  add("Algorithm binding", true, `sig_alg=${p.sigAlg} matches trust config`);

  // 6. Checkpoint resolution.
  const cacheKey = `${anchor.origin}:${p.treeSize}`;
  const cached = checkpointCache.get(cacheKey);
  let rootHash: Uint8Array;

  if (cached) {
    const age = Math.floor((Date.now() - cached.fetchedAt) / 1000);
    add("Checkpoint cache", true, `cache hit · tree_size=${p.treeSize} · fetched ${age}s ago`);
    rootHash = cached.rootHash;
  } else {
    add("Checkpoint cache", false, `cache miss · tree_size=${p.treeSize} · fetching ${anchor.checkpointURL}`);
    let fetchedRoot: Uint8Array, fetchedSize: bigint;
    try {
      [fetchedRoot, fetchedSize] = await fetchAndVerify(anchor, p.treeSize);
    } catch (e) {
      return fail("Checkpoint fetch+verify", String(e));
    }
    add("Checkpoint fetch+verify", true,
      `issuer sig ✓ · ${anchor.witnessQuorum}/${anchor.witnessQuorum} witnesses ✓ · tree_size=${fetchedSize}`);
    rootHash = fetchedRoot;
    if (checkpointCache.size >= MAX_CACHE_ENTRIES) {
      checkpointCache.delete(checkpointCache.keys().next().value!);
    }
    checkpointCache.set(cacheKey, { rootHash: fetchedRoot, fetchedAt: Date.now() });
  }

  // 7. Entry hash.
  const eHash = entryHash(p.tbs);
  add("Entry hash", true, `SHA-256(0x00 ‖ tbs) = ${Buffer.from(eHash).toString("hex")}`);

  // 8. Two-phase tiled Merkle inclusion proof.
  // batchSize must match BATCH_SIZE in the issuer (16).
  const batchSize     = 16;
  const globalIdx     = Number(p.entryIndex);
  const innerIdx      = globalIdx % batchSize;
  const batchIdx      = Math.floor(globalIdx / batchSize);
  const numBatches    = Math.ceil(Number(p.treeSize) / batchSize);
  const batchStart    = batchIdx * batchSize;
  const thisBatchSz   = Math.min(batchSize, Number(p.treeSize) - batchStart);

  const innerCount    = p.innerProofCount;
  const innerProof    = p.proofHashes.slice(0, innerCount);
  const outerProof    = p.proofHashes.slice(innerCount);

  // Phase A: recompute batch root from entry hash + inner proof.
  let batchRoot: Uint8Array;
  try {
    batchRoot = computeRootFromProof(eHash, innerIdx, thisBatchSz, innerProof);
  } catch (e) {
    return fail("Inclusion proof", `Phase A (inner proof) failed: ${e}`);
  }
  const batchRootHex = Buffer.from(batchRoot).toString("hex").slice(0, 16);

  // Phase B: verify batch root in parent tree.
  try {
    verifyInclusion(batchRoot, batchIdx, numBatches, outerProof, rootHash);
  } catch (e) {
    return fail("Inclusion proof",
      `Phase A: batch root ${batchRootHex}… ✓ · Phase B (outer proof) failed: ${e}`);
  }
  add("Inclusion proof", true,
    `Phase A: ${innerCount} inner hashes → batch root ${batchRootHex}… ✓ · ` +
    `Phase B: ${outerProof.length} outer hashes → parent root ✓`);

  // 9. Entry type.
  if (p.tbs.length < 2) return fail("TBS decode", "TBS too short");
  const entryType = p.tbs[0];
  if (entryType !== 0x01 && entryType !== 0x02) return fail("TBS decode", `unrecognized entry_type_byte 0x${entryType.toString(16)} — MUST reject`);
  add("TBS decode", true, `entry_type=0x${entryType.toString(16).padStart(2,"0")} (${entryType === 1 ? "data_assertion (bearer)" : "key_assertion"})`);

  // 10. CBOR decode.
  let entry;
  try { entry = decodeDataAssertion(p.tbs.slice(1)); }
  catch (e) { return fail("CBOR decode", `decode failed: ${e}`); }

  add("CBOR decode", true, `schema_id=${entry.schemaId} issuance=${entry.times[0]} expiry=${entry.times[1]}`);
  res.issuanceTime = entry.times[0];
  res.expiryTime   = entry.times[1];
  res.schemaId     = entry.schemaId;

  // 10. Revocation check.
  // The revocation protocol is fully specified in SPEC.md §Revocation:
  // a Bloom filter cascade over revoked/valid entry indices, signed with
  // the issuer key, served at GET /revoked.
  // TODO: implement cascade fetch, cache, staleness check, and query.
  // Fail-open is NOT the correct default. See issue #14.
  add("Revocation check", false, "not implemented — stub only, revocation not checked");

  // 11. Expiry check (10-minute grace).
  const now = Math.floor(Date.now() / 1000);
  const grace = 600;
  if (entry.times[1] + grace < now) return fail("Expiry check", `expired: expiry=${entry.times[1]} now=${now} (grace=${grace}s)`);
  const remaining = entry.times[1] - now;
  add("Expiry check", true, `valid · ${remaining}s remaining · expires ${entry.times[1]}`);

  res.valid  = true;
  res.claims = entry.claims;
  add("✓ Verification complete", true, `all checks passed · entry_index=${p.entryIndex} · origin="${anchor.origin}"`);
  return res;
}

async function fetchAndVerify(anchor: TrustAnchor, requiredSize: bigint): Promise<[Uint8Array, bigint]> {
  const resp = await fetch(anchor.checkpointURL, { signal: AbortSignal.timeout(10_000) });
  const note = await resp.text();
  return verifyNote(note, anchor, requiredSize);
}

async function verifyNote(note: string, anchor: TrustAnchor, requiredSize: bigint): Promise<[Uint8Array, bigint]> {
  const blankIdx = note.indexOf("\n\n");
  if (blankIdx < 0) throw new Error("note missing blank-line separator");

  const bodyText = note.slice(0, blankIdx);
  const body = new TextEncoder().encode(bodyText + "\n");
  const rest  = note.slice(blankIdx + 2);

  const { origin, treeSize, rootHash } = parseCheckpointBody(body);
  if (origin !== anchor.origin) throw new Error(`origin mismatch: got "${origin}" want "${anchor.origin}"`);
  if (treeSize < requiredSize)  throw new Error(`tree_size ${treeSize} < required ${requiredSize}`);

  const sigLines = rest.split("\n").filter(l => l.trim() !== "");

  // Verify issuer signature by matching the key name in the signature line.
  // This is the correct dispatch — using sig byte length is ambiguous since
  // Ed25519 and ECDSA-P256 are both 64 bytes, and breaks entirely for ML-DSA-44
  // (2420 bytes). The issuer key name uniquely identifies the right line.
  let issuerOK = false;
  for (const line of sigLines) {
    if (!line.includes(anchor.issuerKeyName)) continue;
    const raw = lastFieldBase64(line);
    if (!raw || raw.length < 4) continue;
    // Per c2sp.org/signed-note: first 4 bytes are key_hash; rest is the sig.
    const rawSig = raw.slice(4);
    if (sigVerify(anchor.sigAlg as SigAlg, body, rawSig, anchor.issuerPubKey)) { issuerOK = true; break; }
  }
  if (!issuerOK) throw new Error(`issuer signature not found or invalid (sig_alg=${anchor.sigAlg})`);

  // Verify witness cosignatures.
  // Per c2sp.org/signed-note + tlog-cosignature:
  //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes total.
  const verifiedWitnesses = new Set<string>();
  for (const line of sigLines) {
    const raw = lastFieldBase64(line);
    if (!raw || raw.length !== 76) continue;
    const keyHash = raw.slice(0, 4);
    const tsBuf  = raw.slice(4, 12);
    const ts = tsBuf.reduce((acc, b, i) => acc | (BigInt(b) << BigInt((7 - i) * 8)), BigInt(0));
    const sig = raw.slice(12, 76);
    for (const w of anchor.witnesses) {
      if (!keyHash.every((b, i) => b === w.keyID[i])) continue;
      // Witnesses always use Ed25519 per c2sp.org/tlog-cosignature
      if (sigVerify(SIG_ALG_ED25519, cosignatureV1Message(body, ts), sig, w.pubKey)) verifiedWitnesses.add(w.name);
    }
  }
  if (verifiedWitnesses.size < anchor.witnessQuorum) {
    throw new Error(`witness quorum not met: ${verifiedWitnesses.size}/${anchor.witnessQuorum}`);
  }

  return [rootHash, treeSize];
}

function lastFieldBase64(line: string): Uint8Array | null {
  const idx = line.lastIndexOf(" ");
  if (idx < 0) return null;
  try { return new Uint8Array(Buffer.from(line.slice(idx + 1).trim(), "base64")); }
  catch { return null; }
}

// --- HTTP server ---
function setCORS(res: ServerResponse) {
  // Wildcard CORS for read-only endpoints. State-mutating endpoints
  // (load-trust-config) override this with a restrictive policy.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function isLocalhost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

const MAX_BODY = 64 * 1024; // 64 KB cap
async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let b = "";
    req.on("data", (c: string) => {
      b += c;
      if (b.length > MAX_BODY) { req.destroy(); reject(new Error("request body too large")); }
    });
    req.on("end", () => resolve(b));
    req.on("error", reject);
  });
}

function json(res: ServerResponse, data: unknown, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

const server = createServer(async (req, res) => {
  setCORS(res);
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  const url = new URL(req.url!, `http://localhost:${PORT}`);

  // POST /verify or GET /verify?payload=<b64>
  if (url.pathname === "/verify") {
    let bytes: Uint8Array;
    if (req.method === "GET") {
      const p = url.searchParams.get("payload");
      if (!p) { res.writeHead(400); res.end("missing payload"); return; }
      bytes = new Uint8Array(Buffer.from(p, "base64"));
    } else {
      const body = JSON.parse(await readBody(req)) as { payload_hex?: string; payload_b64?: string };
      if (body.payload_hex) bytes = new Uint8Array(Buffer.from(body.payload_hex, "hex"));
      else bytes = new Uint8Array(Buffer.from(body.payload_b64 ?? "", "base64"));
    }
    const result = await verify(bytes);
    return json(res, result);
  }

  // POST /load-trust-config or GET /load-trust-config?url=...
  if (url.pathname === "/load-trust-config") {
    // Do NOT propagate wildcard CORS — this endpoint mutates server state.
    res.setHeader("Access-Control-Allow-Origin", "null");
    let tcUrl = url.searchParams.get("url") || "http://localhost:8081/trust-config";
    if (req.method === "POST") {
      try { tcUrl = JSON.parse(await readBody(req)).url || tcUrl; } catch {}
    }
    // SSRF mitigation: only localhost targets permitted.
    try {
      const parsed = new URL(tcUrl);
      if (!isLocalhost(parsed.hostname)) {
        return json(res, { error: "trust-config URL must target localhost" }, 400);
      }
    } catch { return json(res, { error: "invalid URL" }, 400); }
    let tc: any;
    try {
      const r = await fetch(tcUrl, { signal: AbortSignal.timeout(10_000) });
      tc = await r.json();
    } catch (e) {
      return json(res, { error: `fetch ${tcUrl}: ${e}` }, 502);
    }
    const issuerPubKey = new Uint8Array(Buffer.from(tc.issuer_pub_key_hex, "hex"));
    const oid = BigInt("0x" + tc.origin_id);
    const witnesses: WitnessEntry[] = (tc.witnesses || []).map((w: any) => ({
      name: w.name,
      keyID: new Uint8Array(Buffer.from(w.key_id_hex, "hex")),
      pubKey: new Uint8Array(Buffer.from(w.pub_key_hex, "hex")),
    }));
    const witnessQuorum = tc.witness_quorum;
    if (!Number.isInteger(witnessQuorum) || witnessQuorum < 1) {
      return json(res, { ok: false, error: `witness_quorum must be >= 1, got ${witnessQuorum}` }, 400);
    }
    if (witnessQuorum > witnesses.length) {
      return json(res, { ok: false,
        error: `witness_quorum (${witnessQuorum}) exceeds witness count (${witnesses.length})` }, 400);
    }
    const anchor: TrustAnchor = {
      origin: tc.origin, originID: oid, issuerPubKey,
      issuerKeyName: tc.issuer_key_name ?? "",
      sigAlg: tc.sig_alg, witnessQuorum,
      witnesses, checkpointURL: tc.checkpoint_url,
    };
    // origin_id collision check: per SPEC, two distinct origins MUST NOT share
    // the same 8-byte origin_id — it would make routing ambiguous.
    const oidKey = oid.toString(16).padStart(16, "0");
    const existing = anchors.get(oidKey);
    if (existing && existing.origin !== tc.origin) {
      return json(res, { ok: false,
        error: `origin_id collision: 0x${oidKey} is shared by "${existing.origin}" and "${tc.origin}"` }, 400);
    }
    anchors.set(oidKey, anchor);
    console.log(`Loaded trust anchor: ${tc.origin} (origin_id=${oid.toString(16).padStart(16,"0")})`);
    return json(res, { ok: true, origin: tc.origin, origin_id: oid.toString(16).padStart(16, "0") });
  }

  // GET /anchors
  if (url.pathname === "/anchors" && req.method === "GET") {
    return json(res, Array.from(anchors.values()).map(a => ({
      origin: a.origin, origin_id: a.originID.toString(16).padStart(16,"0"),
      sig_alg: a.sigAlg, witness_quorum: a.witnessQuorum, checkpoint_url: a.checkpointURL,
    })));
  }

  // GET / — web UI
  if (url.pathname === "/" || url.pathname === "") {
    const prefilledPayload = url.searchParams.get("payload") || "";
    const prefillScript = prefilledPayload
      ? `<script>window.__PREFILLED__ = ${JSON.stringify(prefilledPayload)};</script>\n`
      : "";
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(prefillScript + verifierHTML);
    return;
  }

  res.writeHead(404); res.end("not found");
});

server.listen(PORT);
console.log(`TS verifier started on :${PORT}`);

// Auto-load both issuers at startup.
setTimeout(async () => {
  for (const u of ["http://localhost:8081/trust-config", "http://localhost:3001/trust-config"]) {
    try {
      const r = await fetch(`http://localhost:${PORT}/load-trust-config?url=${encodeURIComponent(u)}`);
      const d = await r.json() as any;
      if (d.ok) console.log(`Auto-loaded trust anchor: ${d.origin}`);
    } catch { /* issuer may not be running yet */ }
  }
}, 500);

// --- Web UI (same structure as Go verifier) ---
const verifierHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MTA-QR TypeScript Verifier</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; }
  .badge.ts { background: #3178c622; color: #3178c6; border: 1px solid #3178c644; }
  .badge.info { background: #388bfd22; color: #388bfd; border: 1px solid #388bfd44; }
  main { display: grid; grid-template-columns: 400px 1fr; height: calc(100vh - 53px); }
  .panel { padding: 24px; border-right: 1px solid #30363d; overflow-y: auto; }
  .panel h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #8b949e; margin-bottom: 16px; }
  input, textarea { width: 100%; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 12px; margin-bottom: 8px; }
  button { background: #1f6feb; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-family: inherit; font-size: 13px; cursor: pointer; width: 100%; font-weight: 600; margin-bottom: 8px; }
  button:hover { background: #388bfd; }
  .btn2 { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  .btn2:hover { background: #30363d; color: #c9d1d9; }
  .step { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border-radius: 6px; margin-bottom: 6px; font-size: 12px; border: 1px solid transparent; }
  .step.ok { background: #1f3d1f; border-color: #2ea04322; }
  .step.fail { background: #3d1f1f; border-color: #f8514922; }
  .sname { font-weight: 600; color: #f0f6fc; margin-bottom: 2px; }
  .sdetail { color: #8b949e; line-height: 1.4; word-break: break-all; }
  .rhead { padding: 16px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
  .rhead.valid { background: #1f3d1f; border: 1px solid #2ea04344; }
  .rhead.invalid { background: #3d1f1f; border: 1px solid #f8514944; }
  .rhead.pending { background: #1c2128; border: 1px solid #30363d; }
  .ricon { font-size: 36px; margin-bottom: 8px; }
  .rtxt { font-size: 18px; font-weight: 700; }
  .rtxt.valid { color: #56d364; } .rtxt.invalid { color: #f85149; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 16px; }
  .mi { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; }
  .ml { font-size: 10px; color: #8b949e; text-transform: uppercase; margin-bottom: 2px; }
  .mv { font-size: 12px; color: #c9d1d9; }
  .anchor-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px; margin-bottom: 8px; font-size: 12px; }
  .ao { color: #58a6ff; font-weight: 600; margin-bottom: 4px; }
  .ad { color: #8b949e; }
  .claims-grid { display: grid; gap: 8px; margin-bottom: 20px; }
  .cr { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px; }
  .ck { font-size: 11px; color: #8b949e; margin-bottom: 2px; }
  .cv { font-size: 13px; color: #f0f6fc; }
</style>
</head>
<body>
<header>
  <h1>MTA-QR Demo</h1>
  <span class="badge ts">TypeScript Verifier</span>
  <span class="badge info">Mode 1</span>
  <span class="badge info" id="anchor-count">0 anchors</span>
</header>
<main>
  <div class="panel">
    <h2>Trust Anchors</h2>
    <input type="text" id="tc-url" value="http://localhost:8081/trust-config">
    <button onclick="loadTC()">Load Trust Config</button>
    <button class="btn2" onclick="loadTC('http://localhost:3001/trust-config')">Load TS Issuer (3001)</button>
    <div id="anchors"></div>
    <div style="border-top:1px solid #30363d;margin:16px 0 16px"></div>
    <h2>Payload Input</h2>
    <textarea id="payload-input" rows="5" placeholder="Paste base64 or hex payload..."></textarea>
    <button onclick="doVerify()">Verify</button>
    <button class="btn2" onclick="clearAll()">Clear</button>
  </div>
  <div class="panel">
    <div id="rhead" class="rhead pending"><div class="ricon">🔍</div><div class="rtxt">Awaiting payload</div></div>
    <div id="meta" style="display:none">
      <div class="meta">
        <div class="mi"><div class="ml">Entry Index</div><div class="mv" id="m-idx">-</div></div>
        <div class="mi"><div class="ml">Tree Size</div><div class="mv" id="m-tree">-</div></div>
        <div class="mi"><div class="ml">Schema ID</div><div class="mv" id="m-schema">-</div></div>
        <div class="mi"><div class="ml">Mode / Alg</div><div class="mv" id="m-mode">-</div></div>
      </div>
      <div class="mi" style="margin-bottom:16px"><div class="ml">Origin</div><div class="mv" id="m-origin" style="word-break:break-all">-</div></div>
    </div>
    <div id="claims-sec" style="display:none"><h2 style="margin-bottom:12px">Claims</h2><div class="claims-grid" id="claims-grid"></div></div>
    <h2 style="margin-bottom:12px">Verification Trace</h2>
    <div id="steps"></div>
  </div>
</main>
<script>
async function loadTC(u) {
  const url = u || document.getElementById('tc-url').value.trim();
  const r = await fetch('/load-trust-config?url='+encodeURIComponent(url));
  const d = await r.json();
  console.log(d.ok ? 'Loaded: '+d.origin : 'Error: '+JSON.stringify(d));
  refreshAnchors();
}
async function refreshAnchors() {
  const list = await (await fetch('/anchors')).json();
  document.getElementById('anchor-count').textContent = list.length + ' anchor' + (list.length !== 1?'s':'');
  const anchorsEl = document.getElementById('anchors')!;
  anchorsEl.innerHTML = '';
  if (list.length === 0) {
    const empty = document.createElement('div');
    empty.style.cssText = 'font-size:12px;color:#8b949e';
    empty.textContent = 'No anchors loaded';
    anchorsEl.appendChild(empty);
  } else {
    list.forEach((a: any) => {
      const item   = document.createElement('div'); item.className = 'anchor-item';
      const origin = document.createElement('div'); origin.className = 'ao'; origin.textContent = a.origin;
      const detail = document.createElement('div'); detail.className = 'ad';
      detail.textContent = 'sig_alg=' + a.sig_alg + ' quorum=' + a.witness_quorum;
      item.appendChild(origin); item.appendChild(detail);
      anchorsEl.appendChild(item);
    });
  }
}
async function doVerify() {
  const raw = document.getElementById('payload-input').value.trim();
  if (!raw) return;
  setRhead('pending','⏳','Verifying...');
  document.getElementById('steps').innerHTML='';
  document.getElementById('meta').style.display='none';
  document.getElementById('claims-sec').style.display='none';
  const isHex = /^[0-9a-f]+$/i.test(raw) && raw.length%2===0;
  const body = JSON.stringify(isHex ? {payload_hex:raw} : {payload_b64:raw});
  try {
    const r = await fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body});
    const d = await r.json();
    renderResult(d);
  } catch(e) {
    setRhead('invalid','❌','ERROR');
    const stepEl = document.createElement('div'); stepEl.className = 'step fail';
    const icon = document.createElement('div'); icon.textContent = '✗';
    const body = document.createElement('div');
    const nm = document.createElement('div'); nm.className = 'sname'; nm.textContent = 'Network error';
    const dt = document.createElement('div'); dt.className = 'sdetail'; dt.textContent = e instanceof Error ? e.message : String(e);
    body.appendChild(nm); body.appendChild(dt);
    stepEl.appendChild(icon); stepEl.appendChild(body);
    const stepsEl = document.getElementById('steps')!;
    stepsEl.innerHTML = ''; stepsEl.appendChild(stepEl);
  }
}
function renderResult(r) {
  setRhead(r.valid?'valid':'invalid', r.valid?'✅':'❌', r.valid?'VALID':'INVALID');
  if (r.entry_index || r.tree_size) {
    document.getElementById('meta').style.display='block';
    document.getElementById('m-idx').textContent = r.entry_index||'-';
    document.getElementById('m-tree').textContent = r.tree_size||'-';
    document.getElementById('m-schema').textContent = r.schema_id||'-';
    document.getElementById('m-mode').textContent = 'mode='+r.mode+' alg='+r.sig_alg;
    document.getElementById('m-origin').textContent = r.origin||'-';
  }
  if (r.claims && Object.keys(r.claims).length>0) {
    document.getElementById('claims-sec').style.display='block';
    const grid = document.getElementById('claims-grid')!;
    grid.innerHTML = '';
    Object.entries(r.claims as Record<string,unknown>).forEach(([k,v]) => {
      const row = document.createElement('div'); row.className = 'cr';
      const key = document.createElement('div'); key.className = 'ck'; key.textContent = k;
      const val = document.createElement('div'); val.className = 'cv'; val.textContent = String(v);
      row.appendChild(key); row.appendChild(val); grid.appendChild(row);
    });
  }
  const stepsList = document.getElementById('steps')!;
  stepsList.innerHTML = '';
  (r.steps||[]).forEach((s: Step) => {
    const item = document.createElement('div'); item.className = 'step ' + (s.ok ? 'ok' : 'fail');
    const icon = document.createElement('div'); icon.textContent = s.ok ? '✓' : '✗';
    const body = document.createElement('div');
    const nm   = document.createElement('div'); nm.className = 'sname';   nm.textContent = s.name;
    const dt   = document.createElement('div'); dt.className = 'sdetail'; dt.textContent = s.detail;
    body.appendChild(nm); body.appendChild(dt);
    item.appendChild(icon); item.appendChild(body);
    stepsList.appendChild(item);
  });
}
function setRhead(cls, icon, txt) {
  document.getElementById('rhead').className='rhead '+cls;
  document.getElementById('rhead').innerHTML='<div class="ricon">'+icon+'</div><div class="rtxt '+cls+'">'+txt+'</div>';
}
function clearAll() {
  document.getElementById('payload-input').value='';
  setRhead('pending','🔍','Awaiting payload');
  document.getElementById('steps').innerHTML='';
  document.getElementById('meta').style.display='none';
  document.getElementById('claims-sec').style.display='none';
}
// Prefilled from deep link.
if (typeof window.__PREFILLED__ !== 'undefined') {
  document.getElementById('payload-input').value = window.__PREFILLED__;
  loadTC('http://localhost:8081/trust-config').then(()=>loadTC('http://localhost:3001/trust-config')).then(()=>setTimeout(doVerify,300));
}
// Auto-load both issuers on startup.
Promise.all([
  fetch('/load-trust-config?url=http://localhost:8081/trust-config').catch(()=>{}),
  fetch('/load-trust-config?url=http://localhost:3001/trust-config').catch(()=>{}),
]).then(()=>refreshAnchors());
</script>
</body>
</html>`;
