/**
 * RFC 6962 §2.1 Merkle tree operations for MTA-QR.
 * Leaf hashes: SHA-256(0x00 || data)
 * Internal nodes: SHA-256(0x01 || left || right)
 * Left/right by entry_index parity: even = left child, odd = right child.
 */
import { createHash } from "crypto";

export function hashLeaf(data: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from([0x00]));
  h.update(data);
  return new Uint8Array(h.digest());
}

export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from([0x01]));
  h.update(left);
  h.update(right);
  return new Uint8Array(h.digest());
}

/** entry_hash = SHA-256(0x00 || tbs). Identical to hashLeaf. */
export function entryHash(tbs: Uint8Array): Uint8Array {
  return hashLeaf(tbs);
}

/** Compute the Merkle root over a slice of leaf hashes. */
export function computeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error("merkle: empty tree");
  return _root(leaves);
}

function _root(nodes: Uint8Array[]): Uint8Array {
  if (nodes.length === 1) return nodes[0];
  const next: Uint8Array[] = [];
  for (let i = 0; i < nodes.length - 1; i += 2) {
    next.push(hashNode(nodes[i], nodes[i + 1]));
  }
  if (nodes.length % 2 === 1) next.push(nodes[nodes.length - 1]);
  return _root(next);
}

/** Build inclusion proof for entryIndex in a tree of the given size. */
export function inclusionProof(
  leaves: Uint8Array[],
  entryIndex: number,
  treeSize: number
): Uint8Array[] {
  if (treeSize === 0) throw new Error("merkle: tree size must be > 0");
  if (entryIndex < 0 || entryIndex >= treeSize)
    throw new Error(`merkle: entry_index ${entryIndex} out of range [0, ${treeSize})`);
  if (leaves.length !== treeSize)
    throw new Error(`merkle: got ${leaves.length} leaves for tree_size ${treeSize}`);
  return _buildProof(leaves, entryIndex);
}

function _buildProof(nodes: Uint8Array[], idx: number): Uint8Array[] {
  if (nodes.length === 1) return [];
  const proof: Uint8Array[] = [];
  let current = [...nodes];
  while (current.length > 1) {
    const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (sibIdx < current.length) {
      proof.push(current[sibIdx]);
    } else {
      proof.push(current[idx]);
    }
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length - 1; i += 2) {
      next.push(hashNode(current[i], current[i + 1]));
    }
    if (current.length % 2 === 1) next.push(current[current.length - 1]);
    idx = Math.floor(idx / 2);
    current = next;
  }
  return proof;
}

/** Verify an inclusion proof against an expected root. */
export function verifyInclusion(
  leafHash: Uint8Array,
  entryIndex: number,
  treeSize: number,
  proof: Uint8Array[],
  expectedRoot: Uint8Array
): void {
  if (treeSize === 0) throw new Error("merkle: tree size must be > 0");
  if (entryIndex < 0 || entryIndex >= treeSize)
    throw new Error(`merkle: entry_index ${entryIndex} out of range`);

  let node = leafHash;
  let idx = entryIndex;
  let size = treeSize;

  for (const sibling of proof) {
    if (idx % 2 === 0) {
      if (idx + 1 === size && size % 2 === 1) {
        idx = Math.floor(idx / 2);
        size = Math.floor((size + 1) / 2);
        continue;
      }
      node = hashNode(node, sibling);
    } else {
      node = hashNode(sibling, node);
    }
    idx = Math.floor(idx / 2);
    size = Math.floor((size + 1) / 2);
  }

  const computed = Buffer.from(node).toString("hex");
  const expected = Buffer.from(expectedRoot).toString("hex");
  if (computed !== expected) {
    throw new Error(`merkle: root mismatch: computed ${computed}, expected ${expected}`);
  }
}

/**
 * Walk a proof path and return the computed root hash without comparing.
 * Used for the inner phase of two-level tiled proof verification — the
 * returned value is the batch root, which is then verified in the outer phase.
 */
export function computeRootFromProof(
  startHash: Uint8Array,
  entryIndex: number,
  treeSize: number,
  proof: Uint8Array[]
): Uint8Array {
  if (treeSize === 0) throw new Error("merkle: tree size must be > 0");
  if (entryIndex < 0 || entryIndex >= treeSize)
    throw new Error(`merkle: entry_index ${entryIndex} out of range [0, ${treeSize})`);

  let node = startHash;
  let idx  = entryIndex;
  let size = treeSize;

  for (const sibling of proof) {
    if (idx % 2 === 0) {
      if (idx + 1 === size && size % 2 === 1) {
        idx  = Math.floor(idx / 2);
        size = Math.floor((size + 1) / 2);
        continue;
      }
      node = hashNode(node, sibling);
    } else {
      node = hashNode(sibling, node);
    }
    idx  = Math.floor(idx / 2);
    size = Math.floor((size + 1) / 2);
  }
  return node;
}
