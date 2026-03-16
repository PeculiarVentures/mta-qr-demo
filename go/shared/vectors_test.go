package vectors_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"fmt"

	"github.com/mta-qr/demo/shared/cascade"
	mtacbor "github.com/mta-qr/demo/shared/cbor"
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/payload"
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

// --- Negative vectors: parser and verifier rejection cases ---

// TestRejectEntryIndexZero verifies that a payload with entry_index=0 is
// decoded without error (it is structurally valid) but exposes entry_index=0,
// which verifiers MUST check and reject before any other processing.
func TestRejectEntryIndexZero(t *testing.T) {
	vs := loadVectors(t)
	v := vs["reject-entry-index-zero"]

	var input struct {
		PayloadHex string `json:"payload_hex"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	b := mustDecodeHex(t, input.PayloadHex)
	p, err := payload.Decode(b)
	if err != nil {
		t.Fatalf("unexpected decode error (entry_index=0 is structurally valid): %v", err)
	}
	if p.EntryIndex != 0 {
		t.Fatalf("expected entry_index=0, got %d — check generator", p.EntryIndex)
	}
	// The rejection must happen at the verifier level, not the parser.
	// Confirm the field is zero so downstream verifier tests can rely on it.
}

// TestRejectTruncatedPayload verifies that payload.Decode returns an error
// when the payload is truncated mid-field (last 5 bytes removed).
func TestRejectTruncatedPayload(t *testing.T) {
	vs := loadVectors(t)
	v := vs["reject-truncated-payload"]

	var input struct {
		PayloadHex string `json:"payload_hex"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	b := mustDecodeHex(t, input.PayloadHex)
	_, err := payload.Decode(b)
	if err == nil {
		t.Error("expected parse error for truncated payload, got nil")
	}
}

// TestRejectTamperedTBS verifies that a tampered TBS produces an entry_hash
// that does not match the inclusion proof, so VerifyInclusion returns an error.
func TestRejectTamperedTBS(t *testing.T) {
	vs := loadVectors(t)
	v := vs["reject-tampered-tbs"]

	var input struct {
		PayloadHex string `json:"payload_hex"`
		RootHex    string `json:"root_hex"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	b := mustDecodeHex(t, input.PayloadHex)
	p, err := payload.Decode(b)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	root := mustDecodeHex(t, input.RootHex)
	entryHash := merkle.EntryHash(p.TBS)

	// The flat VerifyInclusion uses the combined proof.
	// For this 2-entry tree the "inner" and "outer" split is trivial:
	// there is 1 hash and InnerProofCount covers it all. We test the
	// proof path using the raw Merkle function.
	err = merkle.VerifyInclusion(
		entryHash,
		int(p.EntryIndex),
		int(p.TreeSize),
		p.ProofHashes,
		root,
	)
	if err == nil {
		t.Error("expected Merkle VerifyInclusion failure for tampered TBS, got nil")
	}
}

// TestRejectWrongSigAlg verifies that a payload's sig_alg field can be decoded
// and compared against a trust config, and that a mismatch is detectable.
// The actual rejection is enforced by the verifier; this test confirms the
// field is correctly encoded and decoded.
func TestRejectWrongSigAlg(t *testing.T) {
	vs := loadVectors(t)
	v := vs["reject-wrong-sig-alg"]

	var input struct {
		PayloadHex  string `json:"payload_hex"`
		TrustConfig struct {
			SigAlg int `json:"sig_alg"`
		} `json:"trust_config"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	b := mustDecodeHex(t, input.PayloadHex)
	p, err := payload.Decode(b)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	// Payload claims ECDSA P-256 (4), trust config expects Ed25519 (6).
	if p.SigAlg == uint8(input.TrustConfig.SigAlg) {
		t.Fatal("test setup error: payload and trust config have same sig_alg, expected mismatch")
	}
	if p.SigAlg != payload.SigAlgECDSAP256 {
		t.Errorf("expected payload sig_alg=%d (ECDSA P-256), got %d", payload.SigAlgECDSAP256, p.SigAlg)
	}
	if input.TrustConfig.SigAlg != int(payload.SigAlgEd25519) {
		t.Errorf("expected trust config sig_alg=%d (Ed25519), got %d", payload.SigAlgEd25519, input.TrustConfig.SigAlg)
	}
}

func TestCascadeVectorR1(t *testing.T) {
	vs := loadVectors(t)
	v := vs["revocation-cascade-r1"]

	var input struct {
		RevokedIndices []uint64 `json:"revoked_indices"`
		ValidIndices   []uint64 `json:"valid_indices"`
	}
	if err := json.Unmarshal(v.Input, &input); err != nil {
		t.Fatalf("parse input: %v", err)
	}

	var expected struct {
		CascadeHex string `json:"cascade_hex"`
		Queries    []struct {
			Index   uint64 `json:"index"`
			Revoked bool   `json:"revoked"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	c, err := cascade.Build(input.RevokedIndices, input.ValidIndices)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	gotHex := fmt.Sprintf("%x", c.Encode())
	if gotHex != expected.CascadeHex {
		t.Errorf("cascade_hex = %s, want %s", gotHex, expected.CascadeHex)
	}
	for _, q := range expected.Queries {
		if got := c.Query(q.Index); got != q.Revoked {
			t.Errorf("Query(%d) = %v, want %v", q.Index, got, q.Revoked)
		}
	}
}

func TestCascadeVectorR2(t *testing.T) {
	vs := loadVectors(t)
	v := vs["revocation-cascade-r2"]

	var expected struct {
		CascadeHex string `json:"cascade_hex"`
		Queries    []struct {
			Index   uint64 `json:"index"`
			Revoked bool   `json:"revoked"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	c, err := cascade.Build(nil, nil)
	if err != nil {
		t.Fatalf("Build empty: %v", err)
	}

	gotHex := fmt.Sprintf("%x", c.Encode())
	if gotHex != expected.CascadeHex {
		t.Errorf("R2 cascade_hex = %s, want %s", gotHex, expected.CascadeHex)
	}
	for _, q := range expected.Queries {
		if got := c.Query(q.Index); got != q.Revoked {
			t.Errorf("R2 Query(%d) = %v, want %v", q.Index, got, q.Revoked)
		}
	}
}
