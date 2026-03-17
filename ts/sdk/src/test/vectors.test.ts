/**
 * Vector tests for the TypeScript shared library.
 * Loads the same canonical fixtures as the Go tests and asserts exact byte output.
 * A failure here before any application code is debugged points to a specific
 * serialization layer disagreement with the Go implementation.
 */
import { readFileSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { hashLeaf, hashNode, entryHash, computeRoot, inclusionProof, verifyInclusion } from "../merkle.js";
import { encodeTbs as encodeDataAssertion, encodeNullTbs as encodeNullEntry } from "../cbor.js";
import { checkpointBody, checkpointBodyWithRevoc } from "../checkpoint.js";
import { decodePayload } from "../payload.js";

const VECTORS_PATH = join(import.meta.dirname ?? __dirname, "../../../../test-vectors/vectors.json");

interface Vector {
  id: string;
  description: string;
  input: unknown;
  expected: unknown;
}

function loadVectors(): Map<string, Vector> {
  const raw = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as { vectors: Vector[] };
  const m = new Map<string, Vector>();
  for (const v of raw.vectors) m.set(v.id, v);
  return m;
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function fromHex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`  ✗ ${name}\n      ${msg}`);
    failed++;
  }
}

function assert(got: string, want: string, label: string): void {
  if (got !== want) {
    throw new Error(`${label}:\n      got  ${got}\n      want ${want}`);
  }
}

// --- Run tests ---

const vs = loadVectors();
console.log("\nMTA-QR TypeScript vector tests\n");

// Vector 1: checkpoint-body-v1
test("checkpoint-body-v1", () => {
  const v = vs.get("checkpoint-body-v1")!;
  const input = v.input as { origin: string; tree_size: number; root_hash_hex: string };
  const expected = v.expected as { checkpoint_body_hex: string; byte_length: number };

  const rootHash = fromHex(input.root_hash_hex);
  const body = checkpointBody(input.origin, BigInt(input.tree_size), rootHash);

  assert(String(body.length), String(expected.byte_length), "body length");
  assert(hex(body), expected.checkpoint_body_hex, "body hex");

  if (body[body.length - 1] !== 0x0a) {
    throw new Error("body must end with \\n (0x0a)");
  }
});

// Vector 2: null-entry-hash
test("null-entry-hash", () => {
  const v = vs.get("null-entry-hash")!;
  const expected = v.expected as { entry_hash_hex: string };

  const tbs = encodeNullEntry();
  assert(hex(tbs), "00", "null entry TBS");

  const hash = entryHash(tbs);
  assert(hex(hash), expected.entry_hash_hex, "null entry hash");
});

// Vector 3: data-assertion-cbor
test("data-assertion-cbor", () => {
  const v = vs.get("data-assertion-cbor")!;
  const input = v.input as {
    issuance_time: number;
    expiry_time: number;
    schema_id: number;
    claims: Record<string, string>;
  };
  const expected = v.expected as { tbs_hex: string; entry_hash_hex: string };

  const tbs = encodeDataAssertion({
    times: [input.issuance_time, input.expiry_time],
    schemaId: input.schema_id,
    claims: input.claims,
  });

  assert(hex(tbs), expected.tbs_hex, "TBS hex");

  const hash = entryHash(tbs);
  assert(hex(hash), expected.entry_hash_hex, "entry_hash");
});

// Vector 4: merkle-four-entry-tree
test("merkle-four-entry-tree", () => {
  const v = vs.get("merkle-four-entry-tree")!;
  const input = v.input as { leaves: { label: string; data_hex: string }[] };
  const expected = v.expected as {
    leaf_hashes: string[];
    internal_nodes: { H01: string; H23: string };
    root: string;
    inclusion_proof_index2: { entry_index: number; tree_size: number; proof: string[] };
  };

  const leaves = input.leaves.map((l) => hashLeaf(fromHex(l.data_hex)));

  for (let i = 0; i < leaves.length; i++) {
    assert(hex(leaves[i]), expected.leaf_hashes[i], `leaf[${i}]`);
  }

  const H01 = hashNode(leaves[0], leaves[1]);
  const H23 = hashNode(leaves[2], leaves[3]);
  assert(hex(H01), expected.internal_nodes.H01, "H01");
  assert(hex(H23), expected.internal_nodes.H23, "H23");

  const root = computeRoot(leaves);
  assert(hex(root), expected.root, "root");

  const ip = expected.inclusion_proof_index2;
  const proof = inclusionProof(leaves, ip.entry_index, ip.tree_size);
  if (proof.length !== ip.proof.length) {
    throw new Error(`proof length: got ${proof.length}, want ${ip.proof.length}`);
  }
  for (let i = 0; i < proof.length; i++) {
    assert(hex(proof[i]), ip.proof[i], `proof[${i}]`);
  }

  // Round-trip: verify the proof.
  verifyInclusion(leaves[2], ip.entry_index, ip.tree_size, proof, root);
});

// Vector 5: entry-hash-construction
test("entry-hash-construction", () => {
  const v = vs.get("entry-hash-construction")!;
  const input = v.input as { tbs_hex: string };
  const expected = v.expected as { preimage_hex: string; entry_hash_hex: string };

  const tbs = fromHex(input.tbs_hex);

  const preimage = new Uint8Array(1 + tbs.length);
  preimage[0] = 0x00;
  preimage.set(tbs, 1);
  assert(hex(preimage), expected.preimage_hex, "preimage");

  const h = createHash("sha256").update(preimage).digest();
  assert(h.toString("hex"), expected.entry_hash_hex, "entry_hash via raw SHA-256");

  // Also via entryHash helper.
  assert(hex(entryHash(tbs)), expected.entry_hash_hex, "entry_hash via helper");
});

// --- Negative vectors: parser rejection ---
import { decodePayload } from "../payload.js";
import { entryHash, verifyInclusion } from "../merkle.js";

test("reject-entry-index-zero", () => {
  const v = vs.get("reject-entry-index-zero")!;
  const input = v.input as { payload_hex: string };
  const p = decodePayload(fromHex(input.payload_hex));
  // Parser succeeds — rejection happens at the verifier level, not the parser.
  // Confirm the field is zero so downstream tests can rely on it.
  if (p.entryIndex !== 0n) {
    console.log(`  ✗ reject-entry-index-zero: expected entryIndex=0, got ${p.entryIndex}`);
    failed++;
  } else {
    console.log(`  ✓ reject-entry-index-zero: entryIndex=0 correctly decoded`);
    passed++;
  }
});

test("reject-truncated-payload", () => {
  const v = vs.get("reject-truncated-payload")!;
  const input = v.input as { payload_hex: string };
  let threw = false;
  try {
    decodePayload(fromHex(input.payload_hex));
  } catch (_) {
    threw = true;
  }
  if (!threw) {
    console.log(`  ✗ reject-truncated-payload: expected parse error, got none`);
    failed++;
  } else {
    console.log(`  ✓ reject-truncated-payload: truncated payload correctly rejected`);
    passed++;
  }
});

test("reject-tampered-tbs", () => {
  const v = vs.get("reject-tampered-tbs")!;
  const input = v.input as { payload_hex: string; root_hex: string };
  const p = decodePayload(fromHex(input.payload_hex));
  const root = fromHex(input.root_hex);
  const eHash = entryHash(p.tbs);
  // The inclusion proof must fail — tampered TBS produces wrong entry hash.
  let failed_proof = false;
  try {
    verifyInclusion(eHash, Number(p.entryIndex), Number(p.treeSize), p.proofHashes, root);
  } catch (_) {
    failed_proof = true;
  }
  if (!failed_proof) {
    console.log(`  ✗ reject-tampered-tbs: expected Merkle failure, got success`);
    failed++;
  } else {
    console.log(`  ✓ reject-tampered-tbs: tampered TBS correctly fails inclusion proof`);
    passed++;
  }
});

test("reject-wrong-sig-alg", () => {
  const v = vs.get("reject-wrong-sig-alg")!;
  const input = v.input as { payload_hex: string; trust_config: { sig_alg: number } };
  const p = decodePayload(fromHex(input.payload_hex));
  // Payload claims ECDSA P-256 (4), trust config expects Ed25519 (6).
  const mismatch = p.sigAlg !== input.trust_config.sig_alg;
  if (!mismatch) {
    console.log(`  ✗ reject-wrong-sig-alg: expected sig_alg mismatch, got match`);
    failed++;
  } else {
    console.log(`  ✓ reject-wrong-sig-alg: sig_alg=${p.sigAlg} vs trust=${input.trust_config.sig_alg} mismatch detected`);
    passed++;
  }
});

// --- Summary ---
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);


// --- Vector: checkpoint-body-with-revoc ---

const cbwrVec = vs.get("checkpoint-body-with-revoc");
if (cbwrVec) {
  test("checkpoint-body-with-revoc: 4th extension line committed correctly", () => {
    const inp = cbwrVec.input as any;
    const exp = cbwrVec.expected as any;
    const rootHash = fromHex(inp.root_hash_hex);
    const artifact = fromHex(inp.revoc_artifact_hex);
    const body = checkpointBodyWithRevoc(inp.origin, BigInt(inp.tree_size), rootHash, artifact);
    assert(hex(body), exp.body_hex, "body hex");
    if (body.length !== exp.byte_length) throw new Error(`byte_length: got ${body.length} want ${exp.byte_length}`);
    const lines = new TextDecoder().decode(body).trimEnd().split("\n");
    if (lines.length < 4) throw new Error(`expected 4 lines, got ${lines.length}`);
    assert(lines[3], exp.fourth_line, "fourth_line");
  });
}

// --- Vector: mode2-payload-encode ---

const m2Vec = vs.get("mode2-payload-encode");
if (m2Vec) {
  test("mode2-payload-encode: Mode 2 payload has proof_count=0", () => {
    const inp = m2Vec.input as any;
    const exp = m2Vec.expected as any;
    // Decode the canonical payload and verify proof_count and mode
    const decoded = decodePayload(fromHex(exp.payload_hex));
    if (decoded.mode !== 2) throw new Error(`mode: got ${decoded.mode} want 2`);
    if (decoded.proofHashes.length !== exp.proof_count)
      throw new Error(`proof_count: got ${decoded.proofHashes.length} want ${exp.proof_count}`);
    if (decoded.treeSize !== BigInt(inp.tree_size))
      throw new Error(`tree_size: got ${decoded.treeSize} want ${inp.tree_size}`);
    if (decoded.entryIndex !== BigInt(inp.entry_index))
      throw new Error(`entry_index: got ${decoded.entryIndex} want ${inp.entry_index}`);
  });
}

// --- Vector: revoc-checkpoint-commitment ---

const rccVec = vs.get("revoc-checkpoint-commitment");
if (rccVec) {
  test("revoc-checkpoint-commitment: plain vs revoc-extended body produce different sigs", () => {
    const inp = rccVec.input as any;
    const exp = rccVec.expected as any;
    const rootHash = fromHex(inp.root_hash_hex);
    const artifact = fromHex(inp.revoc_artifact_hex);
    const plain = checkpointBody(inp.origin, BigInt(inp.tree_size), rootHash);
    const withRevoc = checkpointBodyWithRevoc(inp.origin, BigInt(inp.tree_size), rootHash, artifact);
    assert(hex(plain), exp.plain_body_hex, "plain_body_hex");
    assert(hex(withRevoc), exp.body_with_revoc_hex, "body_with_revoc_hex");
    if (exp.sigs_differ && hex(plain) === hex(withRevoc))
      throw new Error("expected bodies to differ but they were equal");
  });
}

// --- Vector: reject-revoc-hash-mismatch ---

const rhmVec = vs.get("reject-revoc-hash-mismatch");
if (rhmVec) {
  test("reject-revoc-hash-mismatch: served artifact hash differs from committed hash", () => {
    const inp = rhmVec.input as any;
    const exp = rhmVec.expected as any;
    const served = fromHex(inp.served_revoc_artifact_hex);
    const servedHash = Buffer.from(
      createHash("sha256").update(served).digest()
    ).toString("hex");
    const match = servedHash === inp.committed_hash_hex;
    if (match !== exp.hashes_match)
      throw new Error(`hashes_match: got ${match} want ${exp.hashes_match}`);
  });
}

console.log(`\n${passed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
