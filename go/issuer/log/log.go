// Package log implements the MTA-QR append-only issuance log with a
// tiled two-level Merkle tree matching the browser demo structure.
//
// Tree structure:
//   Batch (inner) tree: each batch holds BATCH_SIZE entries.
//     Proof within a batch: ≤ BATCH_LOG2 hashes.
//   Parent (outer) tree: each leaf is a batch root.
//     Proof within parent: ≤ BATCH_LOG2 hashes (bounded by OUTER_MAX_BATCHES).
//   Checkpoint signs the PARENT tree root, not a flat root over all entries.
//
// This matches the browser demo exactly: same BATCH_SIZE, same OUTER_MAX_BATCHES,
// same wire format (proofCount | innerProofCount | proof...).
package log

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	cborlib "github.com/fxamacker/cbor/v2"
	mtacbor "github.com/mta-qr/demo/shared/cbor"
	"github.com/mta-qr/demo/shared/cascade"
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/payload"
	"github.com/mta-qr/demo/shared/signing"
)

const (
	// BatchSize is the number of entries per batch (inner tree).
	// Must be a power of 2. Matches browser demo BATCH_SIZE.
	BatchSize = 16
	// OuterMaxBatches rolls the outer tree after this many completed batches,
	// bounding the outer proof to ⌈log₂(OuterMaxBatches)⌉ = BatchLog2 hashes.
	OuterMaxBatches = 16
	// BatchLog2 = log₂(BatchSize) = fixed inner proof length.
	BatchLog2 = 4
)

// Entry is a single log entry.
type Entry struct {
	Index     uint64
	TBS       []byte
	EntryHash []byte
}

// Batch is a completed group of BatchSize entries.
// Its Root is cached so it need not be recomputed.
type Batch struct {
	Entries []Entry
	Root    []byte // merkle.Root(entry hashes)
}

// WitnessKey holds a demo witness Ed25519 key pair.
// Witnesses are always Ed25519 per c2sp.org/tlog-cosignature.
type WitnessKey struct {
	Name    string
	KeyID   [4]byte
	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey
}

// Log is the in-memory tiled issuance log.
type Log struct {
	mu               sync.RWMutex
	origin           string
	originID         uint64
	issuer           signing.Signer
	witnesses        []WitnessKey
	batches          []Batch  // completed batches
	currentBatch     []Entry  // in-progress batch (< BatchSize entries)
	latestCkpt       *SignedCheckpoint
	revokedIndices   map[uint64]bool  // entry indices explicitly revoked
	latestRevocation []byte           // signed revocation artifact bytes
}

// SignedCheckpoint is a checkpoint with witness cosignatures attached.
type SignedCheckpoint struct {
	TreeSize  uint64
	RootHash  []byte // parent tree root (root of batch roots)
	Body      []byte
	IssuerSig []byte
	Cosigs    []payload.WitnessCosig
}

// New creates a Log with the given origin and issuer Signer.
func New(origin string, issuer signing.Signer) (*Log, error) {
	witnesses := make([]WitnessKey, 2)
	for i := range witnesses {
		wpub, wpriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("log: generate witness key %d: %w", i, err)
		}
		name := fmt.Sprintf("witness-%d", i)
		witnesses[i] = WitnessKey{
			Name:    name,
			KeyID:   checkpoint.KeyID(name, wpub),
			PubKey:  wpub,
			PrivKey: wpriv,
		}
	}

	l := &Log{
		origin:         origin,
		originID:       checkpoint.OriginID(origin),
		issuer:         issuer,
		witnesses:      witnesses,
		revokedIndices: make(map[uint64]bool),
	}

	if err := l.appendNullEntry(); err != nil {
		return nil, fmt.Errorf("log: init null entry: %w", err)
	}
	if err := l.publishCheckpoint(); err != nil {
		return nil, fmt.Errorf("log: init checkpoint: %w", err)
	}
	return l, nil
}

func (l *Log) appendNullEntry() error {
	tbs := []byte{mtacbor.EntryTypeNull}
	l.currentBatch = append(l.currentBatch, Entry{
		Index:     0,
		TBS:       tbs,
		EntryHash: merkle.EntryHash(tbs),
	})
	return nil
}

// AppendDataAssertion encodes and appends a new DataAssertionLogEntry.
// AppendDataAssertion appends a data assertion entry and returns the global
// entry index and a payload binary. mode selects the payload mode:
//   0 = Mode 0 (embedded checkpoint — fully offline)
//   1 = Mode 1 (cached checkpoint — default)
//   2 = Mode 2 (online proof — smallest payload)
func (l *Log) AppendDataAssertion(issuanceTime, expiryTime, schemaID uint64, claims interface{}, mode uint8) (uint64, []byte, error) {
	tbs, err := mtacbor.EncodeDataAssertion(issuanceTime, expiryTime, schemaID, claims)
	if err != nil {
		return 0, nil, fmt.Errorf("log: encode data assertion: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	globalIdx := l.totalEntries()
	entryHash := merkle.EntryHash(tbs)
	l.currentBatch = append(l.currentBatch, Entry{
		Index:     globalIdx,
		TBS:       tbs,
		EntryHash: entryHash,
	})

	// Finalise batch when full
	if len(l.currentBatch) >= BatchSize {
		if err := l.finaliseBatch(); err != nil {
			return 0, nil, fmt.Errorf("log: finalise batch: %w", err)
		}
	}

	if err := l.publishCheckpointLocked(); err != nil {
		return 0, nil, fmt.Errorf("log: publish checkpoint: %w", err)
	}
	var qrBytes []byte
	switch mode {
	case 0:
		qrBytes, err = l.buildMode0PayloadLocked(globalIdx, tbs)
	case 2:
		qrBytes, err = l.buildMode2PayloadLocked(globalIdx, tbs)
	default:
		qrBytes, err = l.buildMode1PayloadLocked(globalIdx, tbs)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("log: build payload (mode %d): %w", mode, err)
	}
	return globalIdx, qrBytes, nil
}

// finaliseBatch promotes currentBatch to batches[], then resets currentBatch.
// Rolls the outer tree when it reaches OuterMaxBatches to bound the outer proof.
// Must be called with l.mu held (write).
func (l *Log) finaliseBatch() error {
	hashes := make([][]byte, len(l.currentBatch))
	for i, e := range l.currentBatch {
		hashes[i] = e.EntryHash
	}
	root, err := merkle.Root(hashes)
	if err != nil {
		return err
	}
	l.batches = append(l.batches, Batch{Entries: l.currentBatch, Root: root})
	l.currentBatch = nil

	if len(l.batches) >= OuterMaxBatches {
		// DEMO LIMITATION — log continuity is not preserved across rollovers.
		//
		// A production transparency log must be append-only forever: verifiers
		// prove that today's log is a consistent extension of yesterday's by
		// checking a consistency proof between two signed checkpoints. Rolling
		// the outer tree (clearing l.batches) makes that proof impossible across
		// the epoch boundary — a verifier holding an old checkpoint cannot prove
		// that new entries extend it rather than replace it.
		//
		// This rollover exists solely to keep the outer proof bounded at
		// BatchLog2 hashes for the demo (bounding QR payload size). Existing
		// payloads stay self-verifiable because they carry their own proof hashes
		// and do not require a cross-epoch consistency check, but the log-level
		// auditability property is broken at each rollover.
		//
		// Production options that preserve continuity:
		//   (a) Never roll — let the outer proof grow to ⌈log₂(total_batches)⌉
		//       hashes (adds one hash every OuterMaxBatches × BatchSize entries).
		//   (b) Keep old batch roots in a persistent store and carry them forward
		//       into the next epoch's parent tree, then issue a signed consistency
		//       proof at the rollover point.
		//   (c) Switch to a flat tlog-tiles tree (Mode 2) where proof size grows
		//       slowly and standard tooling handles consistency automatically.
		nullTbs := []byte{mtacbor.EntryTypeNull}
		l.batches = nil
		l.currentBatch = []Entry{{
			Index:     0,
			TBS:       nullTbs,
			EntryHash: merkle.EntryHash(nullTbs),
		}}
	}
	return nil
}

// totalEntries returns the total entry count across all batches + current partial batch.
// This is the tree_size value that goes into the checkpoint body.
func (l *Log) totalEntries() uint64 {
	total := uint64(0)
	for _, b := range l.batches {
		total += uint64(len(b.Entries))
	}
	total += uint64(len(l.currentBatch))
	return total
}

// batchRoots builds the ordered slice of batch root hashes for the parent tree.
// Completed batches use their cached root; the partial current batch is computed on the fly.
func (l *Log) batchRoots() ([][]byte, error) {
	roots := make([][]byte, 0, len(l.batches)+1)
	for _, b := range l.batches {
		roots = append(roots, b.Root)
	}
	if len(l.currentBatch) > 0 {
		hashes := make([][]byte, len(l.currentBatch))
		for i, e := range l.currentBatch {
			hashes[i] = e.EntryHash
		}
		partialRoot, err := merkle.Root(hashes)
		if err != nil {
			return nil, err
		}
		roots = append(roots, partialRoot)
	}
	return roots, nil
}

func (l *Log) publishCheckpoint() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.publishCheckpointLocked()
}

func (l *Log) publishCheckpointLocked() error {
	bRoots, err := l.batchRoots()
	if err != nil {
		return fmt.Errorf("compute batch roots: %w", err)
	}
	parentRoot, err := merkle.Root(bRoots)
	if err != nil {
		return fmt.Errorf("compute parent root: %w", err)
	}

	treeSize := l.totalEntries()

	// Build the revocation artifact first so its hash can be committed
	// in the checkpoint body, making the revocation state witnessable.
	artifact, revocErr := l.buildRevocationArtifactLocked()

	// Build checkpoint body — with revoc hash if artifact is available.
	var body []byte
	if revocErr == nil && len(artifact) > 0 {
		body = checkpoint.BodyWithRevoc(l.origin, treeSize, parentRoot, artifact)
	} else {
		body = checkpoint.Body(l.origin, treeSize, parentRoot)
	}

	isig, err := l.issuer.Sign(body)
	if err != nil {
		return fmt.Errorf("issuer sign: %w", err)
	}

	ts := uint64(time.Now().Unix())
	cosigs := make([]payload.WitnessCosig, len(l.witnesses))
	for i, w := range l.witnesses {
		wsig := checkpoint.SignCosignature(body, ts, w.PrivKey)
		var sigArr [64]byte
		copy(sigArr[:], wsig)
		cosigs[i] = payload.WitnessCosig{KeyID: w.KeyID, Timestamp: ts, Signature: sigArr}
	}

	l.latestCkpt = &SignedCheckpoint{
		TreeSize: treeSize, RootHash: parentRoot, Body: body, IssuerSig: isig, Cosigs: cosigs,
	}
	if revocErr == nil {
		l.latestRevocation = artifact
	}
	return nil
}

// buildMode1PayloadLocked constructs the tiled Mode 1 payload for globalIdx.
// Must be called with l.mu held (write, since publishCheckpointLocked must have just run).
func (l *Log) buildMode1PayloadLocked(globalIdx uint64, tbs []byte) ([]byte, error) {
	ckpt := l.latestCkpt
	if ckpt == nil {
		return nil, fmt.Errorf("no checkpoint available")
	}

	// Locate which batch this entry belongs to and its inner index.
	batchIdx := int(globalIdx) / BatchSize
	innerIdx := int(globalIdx) % BatchSize

	// Collect entry hashes for this batch.
	var batchEntryHashes [][]byte
	var batchSize int
	if batchIdx < len(l.batches) {
		// Entry landed in a completed batch (just got finalised).
		b := l.batches[batchIdx]
		for _, e := range b.Entries {
			batchEntryHashes = append(batchEntryHashes, e.EntryHash)
		}
		batchSize = len(b.Entries)
	} else {
		// Entry is in the current (partial) batch.
		for _, e := range l.currentBatch {
			batchEntryHashes = append(batchEntryHashes, e.EntryHash)
		}
		batchSize = len(l.currentBatch)
	}

	// Inner proof: entry → batch root.
	innerProof, err := merkle.InclusionProof(batchEntryHashes, innerIdx, batchSize)
	if err != nil {
		return nil, fmt.Errorf("inner inclusion proof: %w", err)
	}

	// Outer proof: batch root → parent tree root.
	bRoots, err := l.batchRoots()
	if err != nil {
		return nil, fmt.Errorf("batch roots for outer proof: %w", err)
	}
	outerProof, err := merkle.InclusionProof(bRoots, batchIdx, len(bRoots))
	if err != nil {
		return nil, fmt.Errorf("outer inclusion proof: %w", err)
	}

	// Combine into one proof array; InnerProofCount splits them.
	allProof := append(innerProof, outerProof...)

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeCached, SigAlg: l.issuer.SigAlg(),
		DualSig: false, SelfDescrib: true,
		OriginID: l.originID, TreeSize: ckpt.TreeSize,
		EntryIndex: globalIdx, Origin: l.origin,
		ProofHashes:     allProof,
		InnerProofCount: uint8(len(innerProof)),
		TBS:             tbs,
	}
	return payload.Encode(p)
}

// buildMode2PayloadLocked builds a Mode 2 (online reference) payload.
// No proof hashes are embedded; the verifier fetches the inclusion proof
// from a tile server at scan time.
func (l *Log) buildMode2PayloadLocked(globalIdx uint64, tbs []byte) ([]byte, error) {
	ckpt := l.latestCkpt
	if ckpt == nil { return nil, fmt.Errorf("no checkpoint available") }
	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeOnline, SigAlg: l.issuer.SigAlg(),
		DualSig: false, SelfDescrib: true,
		OriginID: l.originID, TreeSize: ckpt.TreeSize,
		EntryIndex: globalIdx, Origin: l.origin,
		ProofHashes: nil, InnerProofCount: 0,
		TBS: tbs,
	}
	return payload.Encode(p)
}

// buildMode0PayloadLocked builds a fully self-contained Mode 0 payload.
// It embeds the two-phase inclusion proof plus the signed checkpoint
// (root hash, issuer signature, and all witness cosignatures) so the
// verifier needs no network access at scan time.
// Must be called with l.mu held (read or write).
func (l *Log) buildMode0PayloadLocked(globalIdx uint64, tbs []byte) ([]byte, error) {
	ckpt := l.latestCkpt
	if ckpt == nil {
		return nil, fmt.Errorf("no checkpoint available")
	}

	batchIdx := int(globalIdx) / BatchSize
	innerIdx := int(globalIdx) % BatchSize

	// Collect batch entry hashes.
	var batchEntryHashes [][]byte
	var batchSize int
	if batchIdx < len(l.batches) {
		b := l.batches[batchIdx]
		for _, e := range b.Entries { batchEntryHashes = append(batchEntryHashes, e.EntryHash) }
		batchSize = len(b.Entries)
	} else {
		for _, e := range l.currentBatch { batchEntryHashes = append(batchEntryHashes, e.EntryHash) }
		batchSize = len(l.currentBatch)
	}

	innerProof, err := merkle.InclusionProof(batchEntryHashes, innerIdx, batchSize)
	if err != nil { return nil, fmt.Errorf("inner inclusion proof: %w", err) }

	bRoots, err := l.batchRoots()
	if err != nil { return nil, fmt.Errorf("batch roots: %w", err) }

	outerProof, err := merkle.InclusionProof(bRoots, batchIdx, len(bRoots))
	if err != nil { return nil, fmt.Errorf("outer inclusion proof: %w", err) }

	allProof := append(innerProof, outerProof...)

	// Mode 0 embeds the checkpoint inline. The verifier reconstructs the
	// checkpoint body from (origin, treeSize, rootHash) using the canonical
	// 3-line form — so Mode 0 must use a 3-line-body signature, not the
	// 4-line body that may be in ckpt.IssuerSig when revoc is active.
	// Re-sign now with the plain 3-line body.
	plainBody := checkpoint.Body(l.origin, ckpt.TreeSize, ckpt.RootHash)
	m0Sig, err := l.issuer.Sign(plainBody)
	if err != nil { return nil, fmt.Errorf("mode 0 issuer sign: %w", err) }
	m0Cosigs := make([]payload.WitnessCosig, len(l.witnesses))
	ts0 := uint64(time.Now().Unix())
	for i, w := range l.witnesses {
		wsig := checkpoint.SignCosignature(plainBody, ts0, w.PrivKey)
		var sigArr [64]byte
		copy(sigArr[:], wsig)
		m0Cosigs[i] = payload.WitnessCosig{KeyID: w.KeyID, Timestamp: ts0, Signature: sigArr}
	}

	p := &payload.Payload{
		Version: 0x01, Mode: payload.ModeEmbedded, SigAlg: l.issuer.SigAlg(),
		DualSig: false, SelfDescrib: true,
		OriginID: l.originID, TreeSize: ckpt.TreeSize,
		EntryIndex: globalIdx, Origin: l.origin,
		ProofHashes:     allProof,
		InnerProofCount: uint8(len(innerProof)),
		TBS:             tbs,
		RootHash:        ckpt.RootHash,
		IssuerSig:       m0Sig,
		Cosigs:          m0Cosigs,
	}
	return payload.Encode(p)
}

// LatestCheckpoint returns the current signed checkpoint.
func (l *Log) LatestCheckpoint() *SignedCheckpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.latestCkpt
}

// IssuerPublicKey returns the raw issuer public key bytes.
func (l *Log) IssuerPublicKey() []byte { return l.issuer.PublicKeyBytes() }

// Witnesses returns the witness key list.
func (l *Log) Witnesses() []WitnessKey { return l.witnesses }

// Origin returns the log origin string.
func (l *Log) Origin() string { return l.origin }

// TrustConfig returns the trust configuration for verifiers.
func (l *Log) TrustConfig() TrustConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()

	witnesses := make([]WitnessConfig, len(l.witnesses))
	for i, w := range l.witnesses {
		witnesses[i] = WitnessConfig{
			Name:   w.Name,
			KeyID:  fmt.Sprintf("%x", w.KeyID),
			PubKey: fmt.Sprintf("%x", w.PubKey),
		}
	}

	baseURL := envOr("MTA_BASE_URL", fmt.Sprintf("http://localhost:%s", issuerPort()))
	checkpointURL := strings.TrimRight(baseURL, "/") + "/checkpoint"

	revocationURL := strings.TrimRight(baseURL, "/") + "/revoked"
	return TrustConfig{
		Origin:        l.origin,
		OriginID:      fmt.Sprintf("%016x", l.originID),
		IssuerPubKey:  fmt.Sprintf("%x", l.issuer.PublicKeyBytes()),
		IssuerKeyName: l.NoteKeyName(),
		SigAlg:        l.issuer.SigAlg(),
		WitnessQuorum: len(l.witnesses),
		Witnesses:     witnesses,
		CheckpointURL: checkpointURL,
		RevocationURL: revocationURL,
		BatchSize:     BatchSize,
	}
}

// NoteKeyName returns the bare key name used in signed note signature lines.
// Per c2sp.org/signed-note, the signature line format is:
//   — <key_name> <base64(4_byte_keyhash || raw_signature)>
// The key_name is the bare name only (not the full verifier key string).
func (l *Log) NoteKeyName() string {
	return fmt.Sprintf("go-issuer-%s", signing.SigAlgName(l.issuer.SigAlg()))
}

// NoteKeyID returns the 4-byte key hash for the issuer key.
// Per c2sp.org/signed-note Ed25519: SHA-256(name || 0x0A || 0x01 || pubkey)[0:4].
func (l *Log) NoteKeyID() [4]byte {
	return checkpoint.KeyID(l.NoteKeyName(), l.issuer.PublicKeyBytes())
}

func issuerPort() string {
	if p := envPort(); p != "" {
		return p
	}
	return "8081"
}

// TrustConfig is the serialized trust anchor for a verifier.
type TrustConfig struct {
	Origin         string          `json:"origin"`
	OriginID       string          `json:"origin_id"`
	IssuerPubKey   string          `json:"issuer_pub_key_hex"`
	IssuerKeyName  string          `json:"issuer_key_name"`
	SigAlg         uint8           `json:"sig_alg"`
	WitnessQuorum  int             `json:"witness_quorum"`
	Witnesses      []WitnessConfig `json:"witnesses"`
	CheckpointURL  string          `json:"checkpoint_url"`
	RevocationURL  string          `json:"revocation_url"`
	BatchSize      int             `json:"batch_size"`
}

// WitnessConfig is a single witness entry.
type WitnessConfig struct {
	Name   string `json:"name"`
	KeyID  string `json:"key_id_hex"`
	PubKey string `json:"pub_key_hex"`
}

// Revoke marks an entry index as revoked and republishes the revocation artifact.
// Returns an error if the entry index has not been issued (> current tree_size).
func (l *Log) Revoke(entryIndex uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if entryIndex == 0 {
		return fmt.Errorf("revoke: entry_index=0 is the null entry and cannot be revoked")
	}
	if entryIndex >= l.totalEntries() {
		return fmt.Errorf("revoke: entry_index %d not yet issued (tree_size=%d)", entryIndex, l.totalEntries())
	}
	l.revokedIndices[entryIndex] = true
	art, err := l.buildRevocationArtifactLocked()
	if err != nil {
		return fmt.Errorf("revoke: build artifact: %w", err)
	}
	l.latestRevocation = art
	return nil
}

// LatestRevocationArtifact returns the current signed revocation artifact bytes,
// or nil if no checkpoint has been published yet.
func (l *Log) LatestRevocationArtifact() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.latestRevocation
}

// IsRevoked reports whether entryIndex is in the revoked set.
func (l *Log) IsRevoked(entryIndex uint64) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.revokedIndices[entryIndex]
}

// buildRevocationArtifactLocked builds and signs the revocation artifact.
// Must be called with l.mu held (write or at publish time).
func (l *Log) buildRevocationArtifactLocked() ([]byte, error) {
	treeSize := l.totalEntries()

	// Build R (revoked) and S (valid non-revoked, non-expired).
	// Index 0 (null entry) is always excluded from both sets.
	now := uint64(time.Now().Unix())
	var revoked, valid []uint64
	for _, batch := range l.batches {
		for _, e := range batch.Entries {
			if e.Index == 0 {
				continue
			}
			if l.revokedIndices[e.Index] {
				revoked = append(revoked, e.Index)
				continue
			}
			// Exclude expired entries (expiry_time < now).
			// TBS[0] is entry_type_byte; for data assertions, expiry is in CBOR field 2.
			if expiry := entryExpiry(e.TBS); expiry > 0 && expiry < now {
				continue
			}
			valid = append(valid, e.Index)
		}
	}
	for _, e := range l.currentBatch {
		if e.Index == 0 {
			continue
		}
		if l.revokedIndices[e.Index] {
			revoked = append(revoked, e.Index)
			continue
		}
		if expiry := entryExpiry(e.TBS); expiry > 0 && expiry < now {
			continue
		}
		valid = append(valid, e.Index)
	}

	casc, err := cascade.Build(revoked, valid)
	if err != nil {
		return nil, fmt.Errorf("cascade build: %w", err)
	}
	cascBytes := casc.Encode()

	// Build the four-line body per SPEC.md §Revocation — Wire Format.
	body := fmt.Sprintf("%s\n%d\nmta-qr-revocation-v1\n%s\n",
		l.origin, treeSize, base64.StdEncoding.EncodeToString(cascBytes))

	// Sign with the issuer key (same key as checkpoints).
	sig, err := l.issuer.Sign([]byte(body))
	if err != nil {
		return nil, fmt.Errorf("sign revocation: %w", err)
	}
	keyID := l.NoteKeyID()
	sigLine := fmt.Sprintf("\n— %s %s\n",
		l.NoteKeyName(),
		base64.StdEncoding.EncodeToString(append(keyID[:], sig...)))

	return []byte(body + sigLine), nil
}

// entryExpiry extracts expiry_time from a data assertion TBS, or 0 if not applicable.
func entryExpiry(tbs []byte) uint64 {
	if len(tbs) < 2 || tbs[0] != 0x01 { // 0x01 = data assertion entry type
		return 0
	}
	// Minimal CBOR decode: map key 2 → [issuance_time, expiry_time].
	// Use the fxamacker/cbor decoder for correctness.
	var entry struct {
		Times [2]uint64 `cbor:"2,keyasint"`
	}
	dm, _ := cborlib.DecOptions{}.DecMode()
	if err := dm.Unmarshal(tbs[1:], &entry); err != nil {
		return 0
	}
	return entry.Times[1]
}
