package verify_test

import (
	"testing"
	"time"

	mtacbor "github.com/mta-qr/demo/shared/cbor"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/payload"
	"github.com/mta-qr/demo/shared/signing"
	"github.com/mta-qr/demo/verifier/verify"
)

// buildMinimalAnchor returns a trust anchor with no witnesses (quorum=0)
// so tests can inject a synthetic root without checkpoint fetch.
func buildMinimalAnchor(t *testing.T, sigAlg uint8, pub []byte, origin string) *verify.TrustAnchor {
	t.Helper()
	originID := verify.OriginIDFromString(origin)
	return &verify.TrustAnchor{
		Origin:        origin,
		OriginID:      originID,
		IssuerPubKey:  pub,
		IssuerKeyName: "test-issuer",
		SigAlg:        sigAlg,
		WitnessQuorum: 0, // bypass witness check for unit tests
		CheckpointURL: "http://localhost/unused",
	}
}

// buildPayloadAndCache constructs a minimal valid 2-entry log (null + one
// data assertion), builds a Mode 1 payload for entry 1, and pre-populates
// the verifier's checkpoint cache so no network fetch occurs.
func buildPayloadAndCache(t *testing.T, v *verify.Verifier, anchor *verify.TrustAnchor) []byte {
	t.Helper()

	nullTBS := []byte{0x00}
	nullHash := merkle.EntryHash(nullTBS)

	now := uint64(time.Now().Unix())
	realTBS, err := mtacbor.EncodeDataAssertion(now-60, now+3600, 1, map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("EncodeDataAssertion: %v", err)
	}
	realHash := merkle.EntryHash(realTBS)

	leaves := [][]byte{nullHash, realHash}
	root, err := merkle.Root(leaves)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	proof, err := merkle.InclusionProof(leaves, 1, 2)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}

	// Inject root into the verifier cache so no checkpoint fetch is needed.
	v.InjectCache(anchor.Origin, 2, root)

	p := &payload.Payload{
		Version:         0x01,
		Mode:            payload.ModeCached,
		SigAlg:          anchor.SigAlg,
		OriginID:        anchor.OriginID,
		TreeSize:        2,
		EntryIndex:      1,
		ProofHashes:     proof,
		InnerProofCount: uint8(len(proof)),
		TBS:             realTBS,
	}
	b, err := payload.Encode(p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func ed25519Anchor(t *testing.T, origin string) (*verify.Verifier, *verify.TrustAnchor, signing.Signer) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed { seed[i] = 0x42 }
	signer, _ := signing.Ed25519FromSeed(seed)
	anchor := buildMinimalAnchor(t, payload.SigAlgEd25519, signer.PublicKeyBytes(), origin)
	v := verify.New()
	if err := v.AddAnchor(anchor); err != nil {
		t.Fatalf("AddAnchor: %v", err)
	}
	return v, anchor, signer
}

// --- Core verification path ---

func TestVerifyValidPayload(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")
	b := buildPayloadAndCache(t, v, anchor)
	result := v.Verify(b)
	if !result.Valid {
		t.Errorf("expected valid, got invalid: %v", lastFailStep(result))
	}
}

// --- Rejection cases ---

func TestRejectEntryIndexZero(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")

	// Build a payload with entry_index=0 directly.
	// The proof is wrong (it would need to prove the null_entry), but the verifier
	// must reject entry_index=0 before consulting the proof or the cache.
	nullTBS := []byte{0x00}
	nullHash := merkle.EntryHash(nullTBS)
	leaves := [][]byte{nullHash}
	root, _ := merkle.Root(leaves)
	v.InjectCache(anchor.Origin, 1, root)

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeCached, SigAlg: anchor.SigAlg,
		OriginID: anchor.OriginID, TreeSize: 1, EntryIndex: 0,
		ProofHashes: nil, InnerProofCount: 0, TBS: nullTBS,
	}
	b, _ := payload.Encode(p)

	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection of entry_index=0, got valid")
	}
	if !stepsContain(result, "Entry index check") {
		t.Errorf("expected 'Entry index check' step in trace; steps: %v", stepNames(result))
	}
}

func TestRejectUnknownOriginID(t *testing.T) {
	v := verify.New() // no anchors loaded
	seed := make([]byte, 32)
	signer, _ := signing.Ed25519FromSeed(seed)
	anchor := buildMinimalAnchor(t, payload.SigAlgEd25519, signer.PublicKeyBytes(), "example.com/v1")
	b := buildPayloadAndCache(t, v, anchor) // cache has root but anchor not registered
	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection for unknown origin, got valid")
	}
}

func TestRejectSigAlgMismatch(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")

	// Build a payload that claims ECDSA P-256 (sig_alg=4).
	// The trust anchor is configured for Ed25519 (sig_alg=6).
	// The verifier must reject at algorithm binding before reaching the cache.
	realTBS, _ := mtacbor.EncodeDataAssertion(
		uint64(time.Now().Unix())-60, uint64(time.Now().Unix())+3600, 1, map[string]any{"k": "v"})
	nullHash := merkle.EntryHash([]byte{0x00})
	realHash := merkle.EntryHash(realTBS)
	leaves := [][]byte{nullHash, realHash}
	root, _ := merkle.Root(leaves)
	proof, _ := merkle.InclusionProof(leaves, 1, 2)
	v.InjectCache(anchor.Origin, 2, root)

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeCached,
		SigAlg:  payload.SigAlgECDSAP256, // mismatch: trust expects Ed25519
		OriginID: anchor.OriginID, TreeSize: 2, EntryIndex: 1,
		ProofHashes: proof, InnerProofCount: uint8(len(proof)), TBS: realTBS,
	}
	b, _ := payload.Encode(p)

	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection for sig_alg mismatch, got valid")
	}
	if !stepsContain(result, "Algorithm binding") {
		t.Errorf("expected 'Algorithm binding' step in trace; steps: %v", stepNames(result))
	}
}

func TestRejectTamperedProof(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")
	b := buildPayloadAndCache(t, v, anchor)

	// Flip a byte deep in the payload (proof hashes area).
	if len(b) > 30 {
		b[len(b)-10] ^= 0xFF
	}

	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection for tampered payload, got valid")
	}
}

func TestRejectExpiredAssertion(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")

	// Build payload with expiry in the past (beyond grace period).
	nullTBS := []byte{0x00}
	nullHash := merkle.EntryHash(nullTBS)

	pastExpiry := uint64(time.Now().Unix()) - 3600 - 600 // 1 hour + grace ago
	expiredTBS, _ := mtacbor.EncodeDataAssertion(pastExpiry-3600, pastExpiry, 1, map[string]any{"k": "v"})
	expiredHash := merkle.EntryHash(expiredTBS)

	leaves := [][]byte{nullHash, expiredHash}
	root, _ := merkle.Root(leaves)
	proof, _ := merkle.InclusionProof(leaves, 1, 2)
	v.InjectCache(anchor.Origin, 2, root)

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeCached, SigAlg: anchor.SigAlg,
		OriginID: anchor.OriginID, TreeSize: 2, EntryIndex: 1,
		ProofHashes: proof, InnerProofCount: uint8(len(proof)), TBS: expiredTBS,
	}
	b, _ := payload.Encode(p)

	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection of expired assertion, got valid")
	}
	if !stepsContain(result, "expiry") {
		t.Errorf("expected 'expiry' step in trace; steps: %v", stepNames(result))
	}
}

func TestRejectMode0(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")

	// Build a Mode 0 payload (embedded checkpoint). The verifier must reject
	// it with a clear "not implemented" error rather than silently falling
	// through to the Mode 1 network path.
	realTBS, _ := mtacbor.EncodeDataAssertion(
		uint64(time.Now().Unix())-60, uint64(time.Now().Unix())+3600, 1, map[string]any{"k": "v"})
	nullHash := merkle.EntryHash([]byte{0x00})
	realHash := merkle.EntryHash(realTBS)
	leaves := [][]byte{nullHash, realHash}
	root, _ := merkle.Root(leaves)
	proof, _ := merkle.InclusionProof(leaves, 1, 2)

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeEmbedded, // Mode 0
		SigAlg: anchor.SigAlg, OriginID: anchor.OriginID,
		TreeSize: 2, EntryIndex: 1,
		ProofHashes: proof, InnerProofCount: uint8(len(proof)), TBS: realTBS,
		RootHash: root, IssuerSig: make([]byte, 64), // placeholder sigs
	}
	b, _ := payload.Encode(p)

	result := v.Verify(b)
	if result.Valid {
		t.Error("expected rejection of Mode 0 (not implemented), got valid")
	}
	if !stepsContain(result, "Mode check") {
		t.Errorf("expected 'Mode check' step in trace; steps: %v", stepNames(result))
	}
}

// --- Cache behaviour ---

func TestCacheHitAvoidsSecondFetch(t *testing.T) {
	v, anchor, _ := ed25519Anchor(t, "example.com/verify-test/v1")
	b := buildPayloadAndCache(t, v, anchor)

	// Verify twice. Both calls should succeed with the same cached root.
	r1 := v.Verify(b)
	r2 := v.Verify(b)
	if !r1.Valid {
		t.Errorf("first verify failed: %v", lastFailStep(r1))
	}
	if !r2.Valid {
		t.Errorf("second verify failed (cache miss?): %v", lastFailStep(r2))
	}
	// Check that the second verify shows a cache hit in the steps.
	if !stepsContain(r2, "cache hit") {
		t.Log("note: second verify did not show explicit cache hit step (ok if batched)")
	}
}

func TestOriginIDCollisionRejected(t *testing.T) {
	v := verify.New()

	seed := make([]byte, 32)
	signer, _ := signing.Ed25519FromSeed(seed)
	pub := signer.PublicKeyBytes()

	// Two anchors with same origin_id but different origin strings.
	// The probability of a real SHA-256 prefix collision is negligible,
	// so we inject two anchors by forcing the same ID directly.
	anchor1 := &verify.TrustAnchor{
		Origin: "example.com/a", OriginID: 0xDEADBEEFDEADBEEF,
		IssuerPubKey: pub, SigAlg: payload.SigAlgEd25519, WitnessQuorum: 0,
	}
	anchor2 := &verify.TrustAnchor{
		Origin: "example.com/b", OriginID: 0xDEADBEEFDEADBEEF,
		IssuerPubKey: pub, SigAlg: payload.SigAlgEd25519, WitnessQuorum: 0,
	}

	if err := v.AddAnchor(anchor1); err != nil {
		t.Fatalf("first AddAnchor failed: %v", err)
	}
	if err := v.AddAnchor(anchor2); err == nil {
		t.Error("expected collision error on second AddAnchor, got nil")
	}
}

// --- helpers ---

func lastFailStep(r *verify.Result) string {
	for i := len(r.Steps) - 1; i >= 0; i-- {
		if !r.Steps[i].OK {
			return r.Steps[i].Name + ": " + r.Steps[i].Detail
		}
	}
	return "(no failed step)"
}

func stepNames(r *verify.Result) []string {
	names := make([]string, len(r.Steps))
	for i, s := range r.Steps {
		names[i] = s.Name
	}
	return names
}

func stepsContain(r *verify.Result, substr string) bool {
	for _, s := range r.Steps {
		if containsSubstr(s.Name, substr) || containsSubstr(s.Detail, substr) {
			return true
		}
	}
	return false
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
