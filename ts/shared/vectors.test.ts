/**
 * Vector tests for the TypeScript shared library.
 * Loads the same canonical fixtures as the Go tests and asserts exact byte output.
 * A failure here before any application code is debugged points to a specific
 * serialization layer disagreement with the Go implementation.
 */
import { readFileSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import { hashLeaf, hashNode, entryHash, computeRoot, inclusionProof, verifyInclusion } from "./merkle.js";
import { encodeDataAssertion, encodeNullEntry } from "./cbor.js";
import { checkpointBody } from "./checkpoint.js";

const VECTORS_PATH = join(import.meta.dirname ?? __dirname, "../../test-vectors/vectors.json");

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

// --- Summary ---
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
