// Package merkle implements RFC 6962 §2.1 Merkle tree operations for MTA-QR.
// Leaf hashes use the 0x00 domain separator; internal node hashes use 0x01.
// Left/right sibling placement is determined by entry_index parity:
//
//	index % 2 == 0 → current node is left child  → SHA-256(0x01 || current || sibling)
//	index % 2 == 1 → current node is right child → SHA-256(0x01 || sibling || current)
package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// HashLeaf computes SHA-256(0x00 || data), the RFC 6962 leaf hash.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// HashNode computes SHA-256(0x01 || left || right), the RFC 6962 internal node hash.
func HashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EntryHash computes the MTA-QR entry hash: SHA-256(0x00 || tbs).
// tbs is entry_type_byte || CBOR(AssertionLogEntry).
// This is identical to HashLeaf — the 0x00 prefix is the RFC 6962 leaf separator.
func EntryHash(tbs []byte) []byte {
	return HashLeaf(tbs)
}

// Root computes the Merkle root over a slice of leaf hashes.
// Returns an error if leaves is empty.
func Root(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle: cannot compute root of empty tree")
	}
	return computeRoot(leaves), nil
}

func computeRoot(nodes [][]byte) []byte {
	if len(nodes) == 1 {
		return nodes[0]
	}
	next := make([][]byte, 0, (len(nodes)+1)/2)
	for i := 0; i < len(nodes)-1; i += 2 {
		next = append(next, HashNode(nodes[i], nodes[i+1]))
	}
	// If odd number of nodes, promote the last one without hashing.
	if len(nodes)%2 == 1 {
		next = append(next, nodes[len(nodes)-1])
	}
	return computeRoot(next)
}

// InclusionProof returns the sibling hashes needed to prove that the leaf
// at entryIndex is included in a tree of the given size.
// Proof hashes are ordered from leaf to root.
func InclusionProof(leaves [][]byte, entryIndex, treeSize int) ([][]byte, error) {
	if treeSize == 0 {
		return nil, errors.New("merkle: tree size must be > 0")
	}
	if entryIndex < 0 || entryIndex >= treeSize {
		return nil, fmt.Errorf("merkle: entry_index %d out of range [0, %d)", entryIndex, treeSize)
	}
	if len(leaves) != treeSize {
		return nil, fmt.Errorf("merkle: got %d leaves for tree_size %d", len(leaves), treeSize)
	}
	return buildProof(leaves, entryIndex), nil
}

func buildProof(nodes [][]byte, idx int) [][]byte {
	if len(nodes) == 1 {
		return nil
	}
	var proof [][]byte
	current := make([][]byte, len(nodes))
	copy(current, nodes)
	for len(current) > 1 {
		// Sibling of idx.
		var sibIdx int
		if idx%2 == 0 {
			sibIdx = idx + 1
		} else {
			sibIdx = idx - 1
		}
		if sibIdx < len(current) {
			proof = append(proof, current[sibIdx])
		} else {
			// Odd node promoted; its sibling is itself (RFC 6962 convention
			// for non-power-of-two trees: unpaired node is carried up).
			proof = append(proof, current[idx])
		}
		// Compute next level.
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current)-1; i += 2 {
			next = append(next, HashNode(current[i], current[i+1]))
		}
		if len(current)%2 == 1 {
			next = append(next, current[len(current)-1])
		}
		idx = idx / 2
		current = next
	}
	return proof
}

// VerifyInclusion verifies that entryHash is included at entryIndex in a tree
// of treeSize whose root is expectedRoot. proof is the slice of sibling hashes
// ordered from leaf to root, as returned by InclusionProof.
func VerifyInclusion(entryHash []byte, entryIndex, treeSize int, proof [][]byte, expectedRoot []byte) error {
	if treeSize == 0 {
		return errors.New("merkle: tree size must be > 0")
	}
	if entryIndex < 0 || entryIndex >= treeSize {
		return fmt.Errorf("merkle: entry_index %d out of range [0, %d)", entryIndex, treeSize)
	}

	node := entryHash
	idx := entryIndex
	size := treeSize

	for _, sibling := range proof {
		if idx%2 == 0 {
			// Current node is left child.
			if idx+1 == size && size%2 == 1 {
				// Unpaired right edge node promoted — no sibling hash consumed.
				idx = idx / 2
				size = (size + 1) / 2
				continue
			}
			node = HashNode(node, sibling)
		} else {
			// Current node is right child.
			node = HashNode(sibling, node)
		}
		idx = idx / 2
		size = (size + 1) / 2
	}

	computed := fmt.Sprintf("%x", node)
	expected := fmt.Sprintf("%x", expectedRoot)
	if computed != expected {
		return fmt.Errorf("merkle: root mismatch: computed %s, expected %s", computed, expected)
	}
	return nil
}

// ComputeRoot walks a proof path and returns the computed root hash.
// It is identical to VerifyInclusion but returns the root instead of
// comparing it, allowing callers to use it as an intermediate value
// (e.g. to compute a batch root as the first phase of a two-level proof).
func ComputeRoot(startHash []byte, entryIndex, treeSize int, proof [][]byte) ([]byte, error) {
	if treeSize == 0 {
		return nil, errors.New("merkle: tree size must be > 0")
	}
	if entryIndex < 0 || entryIndex >= treeSize {
		return nil, fmt.Errorf("merkle: entry_index %d out of range [0, %d)", entryIndex, treeSize)
	}

	node := startHash
	idx  := entryIndex
	size := treeSize

	for _, sibling := range proof {
		if idx%2 == 0 {
			if idx+1 == size && size%2 == 1 {
				idx  = idx / 2
				size = (size + 1) / 2
				continue
			}
			node = HashNode(node, sibling)
		} else {
			node = HashNode(sibling, node)
		}
		idx  = idx / 2
		size = (size + 1) / 2
	}
	return node, nil
}
