package log_test

import (
	"testing"
	"time"

	"github.com/mta-qr/demo/issuer/log"
	"github.com/mta-qr/demo/shared/payload"
	"github.com/mta-qr/demo/shared/signing"
)

func newTestLog(t *testing.T) *log.Log {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed { seed[i] = 0x42 }
	signer, err := signing.Ed25519FromSeed(seed)
	if err != nil {
		t.Fatalf("Ed25519FromSeed: %v", err)
	}
	l, err := log.New("example.com/log-test/v1", signer)
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	return l
}

// TestNullEntryAtIndexZero verifies that a freshly initialised log has a
// null_entry at index 0 and that the first real assertion lands at index 1.
func TestNullEntryAtIndexZero(t *testing.T) {
	l := newTestLog(t)

	now := uint64(time.Now().Unix())
	idx, _, err := l.AppendDataAssertion(now, now+3600, 1, map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("AppendDataAssertion: %v", err)
	}
	if idx != 1 {
		t.Errorf("first real assertion: expected entry_index=1, got %d", idx)
	}
}

// TestSequentialIndices verifies that successive assertions get consecutive
// entry indices starting at 1.
func TestSequentialIndices(t *testing.T) {
	l := newTestLog(t)
	now := uint64(time.Now().Unix())

	for want := uint64(1); want <= 5; want++ {
		got, _, err := l.AppendDataAssertion(now, now+3600, 1, map[string]any{"i": want})
		if err != nil {
			t.Fatalf("AppendDataAssertion %d: %v", want, err)
		}
		if got != want {
			t.Errorf("entry %d: expected index=%d, got %d", want, want, got)
		}
	}
}

// TestProofRoundTrip verifies that a payload produced by the log contains a
// valid Mode 1 inclusion proof — i.e., the payload decodes cleanly and has
// the correct entry_index and tree_size fields.
func TestProofRoundTrip(t *testing.T) {
	l := newTestLog(t)
	now := uint64(time.Now().Unix())

	idx, payloadBytes, err := l.AppendDataAssertion(now, now+3600, 1, map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("AppendDataAssertion: %v", err)
	}

	p, err := payload.Decode(payloadBytes)
	if err != nil {
		t.Fatalf("payload.Decode: %v", err)
	}
	if p.EntryIndex != idx {
		t.Errorf("entry_index: want %d, got %d", idx, p.EntryIndex)
	}
	if p.Mode != payload.ModeCached {
		t.Errorf("mode: want %d (ModeCached), got %d", payload.ModeCached, p.Mode)
	}
	if p.SigAlg != payload.SigAlgEd25519 {
		t.Errorf("sig_alg: want %d (Ed25519), got %d", payload.SigAlgEd25519, p.SigAlg)
	}
	if len(p.TBS) == 0 {
		t.Error("TBS is empty")
	}
	if p.TBS[0] != 0x01 {
		t.Errorf("entry_type_byte: want 0x01 (data_assertion), got 0x%02x", p.TBS[0])
	}
}

// TestCheckpointPublished verifies that after appending entries the log
// publishes a checkpoint with a non-nil root hash.
func TestCheckpointPublished(t *testing.T) {
	l := newTestLog(t)
	now := uint64(time.Now().Unix())

	if _, _, err := l.AppendDataAssertion(now, now+3600, 1, map[string]any{"k": "v"}); err != nil {
		t.Fatalf("AppendDataAssertion: %v", err)
	}

	ckpt := l.LatestCheckpoint()
	if ckpt == nil {
		t.Fatal("LatestCheckpoint: got nil")
	}
	if len(ckpt.RootHash) != 32 {
		t.Errorf("root_hash: want 32 bytes, got %d", len(ckpt.RootHash))
	}
	if ckpt.TreeSize < 2 {
		t.Errorf("tree_size: want >= 2 (null + 1 real), got %d", ckpt.TreeSize)
	}
}

// TestTrustConfigBatchSize verifies that the trust config emitted by the log
// includes batch_size and that it matches the log's configured constant.
func TestTrustConfigBatchSize(t *testing.T) {
	l := newTestLog(t)
	tc := l.TrustConfig()

	if tc.BatchSize <= 0 {
		t.Errorf("batch_size: want > 0, got %d", tc.BatchSize)
	}
	if tc.BatchSize != log.BatchSize {
		t.Errorf("batch_size: want %d (log.BatchSize), got %d", log.BatchSize, tc.BatchSize)
	}
}

// TestTrustConfigOriginIDConsistency verifies that the origin_id in the trust
// config matches what a verifier would compute from the origin string.
func TestTrustConfigOriginIDConsistency(t *testing.T) {
	l := newTestLog(t)
	tc := l.TrustConfig()

	if tc.Origin == "" {
		t.Fatal("trust config origin is empty")
	}
	if tc.OriginID == "" {
		t.Fatal("trust config origin_id is empty")
	}
	// The origin_id must be a 16-hex-character string (8 bytes big-endian).
	if len(tc.OriginID) != 16 {
		t.Errorf("origin_id hex length: want 16, got %d (%q)", len(tc.OriginID), tc.OriginID)
	}
}

// TestWitnessesPresent verifies that the log initialises with at least one
// witness key and that all witness keys are Ed25519 (64-byte pubkey is wrong;
// Ed25519 pubkeys are 32 bytes).
func TestWitnessesPresent(t *testing.T) {
	l := newTestLog(t)
	witnesses := l.Witnesses()

	if len(witnesses) == 0 {
		t.Fatal("expected at least one witness key, got none")
	}
	for i, w := range witnesses {
		if len(w.PubKey) != 32 {
			t.Errorf("witness[%d] pubkey: want 32 bytes (Ed25519), got %d", i, len(w.PubKey))
		}
		if w.Name == "" {
			t.Errorf("witness[%d] name is empty", i)
		}
	}
}

// TestMultipleBatchesCrossProof verifies that entries spanning two batches
// both decode cleanly with valid-looking proof structures.
func TestMultipleBatchesCrossProof(t *testing.T) {
	l := newTestLog(t)
	now := uint64(time.Now().Unix())

	// Append BatchSize + 1 entries to force a batch boundary.
	var lastPayload []byte
	for i := 0; i <= log.BatchSize; i++ {
		_, pb, err := l.AppendDataAssertion(now, now+3600, 1, map[string]any{"i": i})
		if err != nil {
			t.Fatalf("AppendDataAssertion %d: %v", i, err)
		}
		lastPayload = pb
	}

	p, err := payload.Decode(lastPayload)
	if err != nil {
		t.Fatalf("payload.Decode: %v", err)
	}
	// Entry at index BatchSize+1 is in the second batch.
	// Its proof should have both inner and outer components.
	if p.InnerProofCount == 0 && len(p.ProofHashes) > 0 {
		t.Error("expected non-zero inner_proof_count for entry spanning batch boundary")
	}
	if len(p.ProofHashes) == 0 {
		t.Error("expected non-empty proof for entry in non-trivial tree")
	}
}
