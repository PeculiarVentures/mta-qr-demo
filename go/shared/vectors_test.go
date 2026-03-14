package vectors_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	mtacbor "github.com/mta-qr/demo/shared/cbor"
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/merkle"
)

// vectorFile is the path to the canonical test vectors JSON, relative to
// the repo root. Adjust if running from a different working directory.
const vectorFile = "../../test-vectors/vectors.json"

type vectors struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Expected    json.RawMessage `json:"expected"`
}

func loadVectors(t *testing.T) map[string]vector {
	t.Helper()
	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var vs vectors
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	m := make(map[string]vector, len(vs.Vectors))
	for _, v := range vs.Vectors {
		m[v.ID] = v
	}
	return m
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// --- Vector: checkpoint-body-v1 ---

func TestCheckpointBody(t *testing.T) {
	vs := loadVectors(t)
	v := vs["checkpoint-body-v1"]

	var input struct {
		Origin      string `json:"origin"`
		TreeSize    uint64 `json:"tree_size"`
		RootHashHex string `json:"root_hash_hex"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	var expected struct {
		CheckpointBodyHex string `json:"checkpoint_body_hex"`
		ByteLength        int    `json:"byte_length"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	rootHash := mustDecodeHex(t, input.RootHashHex)
	body := checkpoint.Body(input.Origin, input.TreeSize, rootHash)

	if len(body) != expected.ByteLength {
		t.Errorf("body length: got %d, want %d", len(body), expected.ByteLength)
	}

	gotHex := hex.EncodeToString(body)
	if gotHex != expected.CheckpointBodyHex {
		t.Errorf("checkpoint body mismatch:\ngot  %s\nwant %s", gotHex, expected.CheckpointBodyHex)
	}

	// Verify the body ends with \n (not just the whole string but literally the last byte).
	if body[len(body)-1] != '\n' {
		t.Errorf("checkpoint body must end with \\n; last byte is 0x%02x", body[len(body)-1])
	}
}

// --- Vector: null-entry-hash ---

func TestNullEntryHash(t *testing.T) {
	vs := loadVectors(t)
	v := vs["null-entry-hash"]

	var expected struct {
		EntryHashHex string `json:"entry_hash_hex"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	// null_entry TBS is a single 0x00 byte.
	tbs := []byte{0x00}
	hash := merkle.EntryHash(tbs)
	gotHex := hex.EncodeToString(hash)

	if gotHex != expected.EntryHashHex {
		t.Errorf("null entry hash mismatch:\ngot  %s\nwant %s", gotHex, expected.EntryHashHex)
	}
}

// --- Vector: data-assertion-cbor ---

func TestDataAssertionCBOR(t *testing.T) {
	vs := loadVectors(t)
	v := vs["data-assertion-cbor"]

	var input struct {
		IssuanceTime uint64         `json:"issuance_time"`
		ExpiryTime   uint64         `json:"expiry_time"`
		SchemaID     uint64         `json:"schema_id"`
		Claims       map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	var expected struct {
		TBSHex        string `json:"tbs_hex"`
		EntryHashHex  string `json:"entry_hash_hex"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	tbs, err := mtacbor.EncodeDataAssertion(
		input.IssuanceTime,
		input.ExpiryTime,
		input.SchemaID,
		input.Claims,
	)
	if err != nil {
		t.Fatalf("EncodeDataAssertion: %v", err)
	}

	gotTBSHex := hex.EncodeToString(tbs)
	if gotTBSHex != expected.TBSHex {
		t.Errorf("TBS mismatch:\ngot  %s\nwant %s", gotTBSHex, expected.TBSHex)
	}

	entryHash := merkle.EntryHash(tbs)
	gotHashHex := hex.EncodeToString(entryHash)
	if gotHashHex != expected.EntryHashHex {
		t.Errorf("entry_hash mismatch:\ngot  %s\nwant %s", gotHashHex, expected.EntryHashHex)
	}

	// Canonicalization round-trip check.
	if err := mtacbor.RoundTripCanonical(tbs[1:]); err != nil {
		t.Errorf("CBOR round-trip canonical check failed: %v", err)
	}
}

// --- Vector: merkle-four-entry-tree ---

func TestMerkleFourEntryTree(t *testing.T) {
	vs := loadVectors(t)
	v := vs["merkle-four-entry-tree"]

	var input struct {
		Leaves []struct {
			Label   string `json:"label"`
			DataHex string `json:"data_hex"`
		} `json:"leaves"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	var expected struct {
		LeafHashes []string `json:"leaf_hashes"`
		InternalNodes struct {
			H01 string `json:"H01"`
			H23 string `json:"H23"`
		} `json:"internal_nodes"`
		Root                 string `json:"root"`
		InclusionProofIndex2 struct {
			EntryIndex int      `json:"entry_index"`
			TreeSize   int      `json:"tree_size"`
			Proof      []string `json:"proof"`
		} `json:"inclusion_proof_index2"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	// Compute leaf hashes using SHA-256(0x00 || data).
	leaves := make([][]byte, len(input.Leaves))
	for i, l := range input.Leaves {
		data := mustDecodeHex(t, l.DataHex)
		leaves[i] = merkle.HashLeaf(data)
		gotHex := hex.EncodeToString(leaves[i])
		if gotHex != expected.LeafHashes[i] {
			t.Errorf("leaf[%d] hash mismatch:\ngot  %s\nwant %s", i, gotHex, expected.LeafHashes[i])
		}
	}

	// Compute internal nodes.
	H01 := merkle.HashNode(leaves[0], leaves[1])
	H23 := merkle.HashNode(leaves[2], leaves[3])
	gotH01 := hex.EncodeToString(H01)
	gotH23 := hex.EncodeToString(H23)
	if gotH01 != expected.InternalNodes.H01 {
		t.Errorf("H01 mismatch:\ngot  %s\nwant %s", gotH01, expected.InternalNodes.H01)
	}
	if gotH23 != expected.InternalNodes.H23 {
		t.Errorf("H23 mismatch:\ngot  %s\nwant %s", gotH23, expected.InternalNodes.H23)
	}

	// Compute root.
	root, err := merkle.Root(leaves)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	gotRoot := hex.EncodeToString(root)
	if gotRoot != expected.Root {
		t.Errorf("root mismatch:\ngot  %s\nwant %s", gotRoot, expected.Root)
	}

	// Validate inclusion proof for entry_index 2.
	ip := expected.InclusionProofIndex2
	proof, err := merkle.InclusionProof(leaves, ip.EntryIndex, ip.TreeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if len(proof) != len(ip.Proof) {
		t.Fatalf("proof length: got %d, want %d", len(proof), len(ip.Proof))
	}
	for i, h := range proof {
		gotHex := hex.EncodeToString(h)
		if gotHex != ip.Proof[i] {
			t.Errorf("proof[%d] mismatch:\ngot  %s\nwant %s", i, gotHex, ip.Proof[i])
		}
	}

	// Verify the proof round-trips.
	if err := merkle.VerifyInclusion(leaves[2], ip.EntryIndex, ip.TreeSize, proof, root); err != nil {
		t.Errorf("VerifyInclusion failed: %v", err)
	}
}

// --- Vector: entry-hash-construction ---

func TestEntryHashConstruction(t *testing.T) {
	vs := loadVectors(t)
	v := vs["entry-hash-construction"]

	var input struct {
		TBSHex string `json:"tbs_hex"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	var expected struct {
		PreimageHex  string `json:"preimage_hex"`
		EntryHashHex string `json:"entry_hash_hex"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	tbs := mustDecodeHex(t, input.TBSHex)

	// Verify preimage = 0x00 || tbs.
	preimage := append([]byte{0x00}, tbs...)
	gotPreimageHex := hex.EncodeToString(preimage)
	if gotPreimageHex != expected.PreimageHex {
		t.Errorf("preimage mismatch:\ngot  %s\nwant %s", gotPreimageHex, expected.PreimageHex)
	}

	// Verify entry hash.
	h := sha256.Sum256(preimage)
	gotHashHex := hex.EncodeToString(h[:])
	if gotHashHex != expected.EntryHashHex {
		t.Errorf("entry_hash mismatch:\ngot  %s\nwant %s", gotHashHex, expected.EntryHashHex)
	}

	// Also verify via the EntryHash helper.
	entryHash := merkle.EntryHash(tbs)
	gotHelperHex := hex.EncodeToString(entryHash)
	if gotHelperHex != expected.EntryHashHex {
		t.Errorf("EntryHash helper mismatch:\ngot  %s\nwant %s", gotHelperHex, expected.EntryHashHex)
	}
}
