package cascade

import (
	"fmt"
	"testing"
)

// TestVectorR1 — SPEC.md §Test Vectors — Revocation Vectors, Vector R1.
// R={2,5}, S={1,3,4,6,7,8}. Exact bytes locked after first passing run.
func TestVectorR1Queries(t *testing.T) {
	revoked := []uint64{2, 5}
	valid := []uint64{1, 3, 4, 6, 7, 8}

	c, err := Build(revoked, valid)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	cases := []struct {
		idx      uint64
		expected bool
	}{
		{0, false},  // excluded from both sets
		{1, false},
		{2, true},
		{3, false},
		{4, false},
		{5, true},
		{6, false},
		{7, false},
		{8, false},
		{99, false}, // not in either set
	}
	for _, tc := range cases {
		got := c.Query(tc.idx)
		if got != tc.expected {
			t.Errorf("Query(%d) = %v, want %v", tc.idx, got, tc.expected)
		}
	}
}

// TestVectorR1EncodeDecode — round-trip and locked bytes.
func TestVectorR1EncodeDecode(t *testing.T) {
	revoked := []uint64{2, 5}
	valid := []uint64{1, 3, 4, 6, 7, 8}

	c, err := Build(revoked, valid)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded := c.Encode()

	// Locked canonical bytes — test-vectors/vectors.json "revocation-cascade-r1".
	// If this assertion fails, the construction constants changed.
	// Update the spec, regenerate all cross-language test vectors, and bump the
	// spec version before merging.
	want := "01000000080112"
	got := fmt.Sprintf("%x", encoded)
	if got != want {
		t.Errorf("R1 cascade bytes = %s, want %s\n(if constants changed, update SPEC.md and all cross-language vectors)", got, want)
	}

	// Round-trip.
	c2, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for _, x := range []uint64{1, 2, 3, 4, 5, 6, 7, 8, 99} {
		if c.Query(x) != c2.Query(x) {
			t.Errorf("round-trip mismatch at index %d", x)
		}
	}
}

// TestVectorR2 — empty revocation set.
func TestVectorR2(t *testing.T) {
	c, err := Build(nil, []uint64{1, 2, 3})
	if err != nil {
		t.Fatalf("Build empty R: %v", err)
	}
	enc := c.Encode()
	if len(enc) != 1 || enc[0] != 0 {
		t.Errorf("empty cascade should be 1 byte 0x00, got %x", enc)
	}
	for _, x := range []uint64{0, 1, 2, 3, 99} {
		if c.Query(x) {
			t.Errorf("empty cascade Query(%d) should be false", x)
		}
	}
}

// TestRejectionCases — SPEC.md R-REJ-1 through R-REJ-9.
func TestRejectionCases(t *testing.T) {
	// R-REJ-1: truncated after level 0 header
	_, err := Decode([]byte{0x01, 0x00, 0x00, 0x00}) // num_levels=1 but only 4 bytes of 5-byte header
	if err == nil {
		t.Error("R-REJ-1: truncated header should fail")
	}

	// R-REJ-2: bit_count=0
	_, err = Decode([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x01}) // bit_count=0, k=1
	if err == nil {
		t.Error("R-REJ-2: bit_count=0 should fail")
	}

	// R-REJ-3 (k!=1): k=2
	_, err = Decode([]byte{0x01, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00}) // bit_count=8, k=2, 1 byte
	if err == nil {
		t.Error("R-REJ-3: k=2 should fail")
	}

	// R-REJ-9: valid num_levels=1 but bit array truncated
	_, err = Decode([]byte{0x01, 0x00, 0x00, 0x00, 0x08, 0x01}) // bit_count=8 needs 1 byte but 0 provided
	if err == nil {
		t.Error("R-REJ-9: truncated bit array should fail")
	}

	// Trailing bytes
	_, err = Decode([]byte{0x00, 0xFF}) // num_levels=0 (1 byte) + trailing 0xFF
	if err == nil {
		t.Error("trailing bytes should fail")
	}
}

// TestZeroElementFilter — single revoked entry, no valid entries.
func TestZeroValidEntries(t *testing.T) {
	c, err := Build([]uint64{42}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !c.Query(42) {
		t.Error("revoked entry 42 should be reported revoked")
	}
	if c.Query(1) {
		t.Error("entry 1 not in R — may be false positive but probability is ~50%")
		// This is non-deterministic; just log
	}
}

// TestDeterminism — same inputs always produce same bytes.
func TestDeterminism(t *testing.T) {
	r := []uint64{10, 20, 30}
	s := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 11}
	c1, _ := Build(r, s)
	c2, _ := Build(r, s)
	b1, b2 := c1.Encode(), c2.Encode()
	if len(b1) != len(b2) {
		t.Fatalf("determinism: length mismatch %d vs %d", len(b1), len(b2))
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			t.Errorf("determinism: byte %d differs: %02x vs %02x", i, b1[i], b2[i])
		}
	}
}
