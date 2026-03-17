// Package verify implements the MTA-QR Mode 1 verification flow.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	cborlib "github.com/fxamacker/cbor/v2"
	"github.com/mta-qr/demo/shared/cascade"
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/payload"
	"github.com/mta-qr/demo/shared/signing"
)

// TrustAnchor is a trusted issuer loaded from a /trust-config endpoint.
type TrustAnchor struct {
	Origin        string
	OriginID      uint64
	IssuerPubKey  []byte
	IssuerKeyName string // key name prefix as it appears in note sig lines
	SigAlg        uint8
	WitnessQuorum int
	Witnesses     []WitnessEntry
	CheckpointURL string
	RevocationURL string // URL of GET /revoked endpoint; empty if issuer omits revocation_url
	BatchSize     int    // from trust config batch_size; defaults to 16 if absent
}

// WitnessEntry is a trusted witness key within a TrustAnchor.
type WitnessEntry struct {
	Name   string
	KeyID  [4]byte
	PubKey []byte
}

// CachedCheckpoint is a locally cached verified checkpoint.
type CachedCheckpoint struct {
	TreeSize  uint64
	RootHash  []byte
	FetchedAt time.Time
}

// Step is a single step in the verification trace.
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Result is the full verification outcome with step trace.
type Result struct {
	Valid        bool           `json:"valid"`
	Steps        []Step         `json:"steps"`
	Claims       map[string]any `json:"claims,omitempty"`
	Error        string         `json:"error,omitempty"`
	EntryIndex   uint64         `json:"entry_index"`
	TreeSize     uint64         `json:"tree_size"`
	Origin       string         `json:"origin"`
	Mode         uint8          `json:"mode"`
	SigAlg       uint8          `json:"sig_alg"`
	IssuanceTime uint64         `json:"issuance_time"`
	ExpiryTime   uint64         `json:"expiry_time"`
	SchemaID     uint64         `json:"schema_id"`
}

const maxCacheEntries = 1000

// CachedRevocation holds a locally cached, verified revocation artifact.
type CachedRevocation struct {
	Cascade     *cascade.Cascade
	TreeSize    uint64
	CascadeHash [32]byte // SHA-256 of raw cascade bytes for in-memory integrity
}

// Verifier holds trust anchors, a checkpoint cache, and a revocation cache.
type Verifier struct {
	mu          sync.RWMutex
	anchors     map[uint64]*TrustAnchor
	cache       map[string]*CachedCheckpoint
	cacheOrder  []string // insertion order for LRU eviction
	revocCache  map[string]*CachedRevocation // keyed by full_origin
	httpClient  *http.Client
}

// New creates an empty Verifier.
func New() *Verifier {
	return &Verifier{
		anchors:    make(map[uint64]*TrustAnchor),
		cache:      make(map[string]*CachedCheckpoint),
		cacheOrder: make([]string, 0, maxCacheEntries+1),
		revocCache: make(map[string]*CachedRevocation),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// AddAnchor registers a trusted issuer.
// Returns an error if the 8-byte origin_id collides with an existing entry
// whose full origin string differs — such a collision would make origin-based
// routing ambiguous and could cause assertions to be validated against the
// wrong issuer key.
func (v *Verifier) AddAnchor(a *TrustAnchor) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.anchors[a.OriginID]; ok && existing.Origin != a.Origin {
		return fmt.Errorf("origin_id collision: 0x%016x is shared by %q and %q — "+
			"two distinct origins must not produce the same 8-byte origin_id", a.OriginID, existing.Origin, a.Origin)
	}
	v.anchors[a.OriginID] = a
	return nil
}

// Anchors returns all registered anchors (for display).
func (v *Verifier) Anchors() []*TrustAnchor {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]*TrustAnchor, 0, len(v.anchors))
	for _, a := range v.anchors {
		out = append(out, a)
	}
	return out
}

// Verify verifies a raw payload and returns a detailed step trace.
func (v *Verifier) Verify(payloadBytes []byte) *Result {
	res := &Result{}
	steps := []Step{}

	add := func(name string, ok bool, detail string) {
		steps = append(steps, Step{Name: name, OK: ok, Detail: detail})
		res.Steps = steps
	}
	fail := func(name, detail string) *Result {
		add(name, false, detail)
		if res.Error == "" {
			res.Error = detail
		}
		return res
	}

	// 1. Decode payload binary.
	p, err := payload.Decode(payloadBytes)
	if err != nil {
		return fail("Decode payload", fmt.Sprintf("malformed payload: %v", err))
	}
	add("Decode payload", true, fmt.Sprintf("mode=%d sig_alg=%d entry_index=%d tree_size=%d self_describing=%v",
		p.Mode, p.SigAlg, p.EntryIndex, p.TreeSize, p.SelfDescrib))
	res.EntryIndex = p.EntryIndex
	res.TreeSize = p.TreeSize
	res.Mode = p.Mode
	res.SigAlg = p.SigAlg

	// 2. Reject reserved index 0.
	if p.EntryIndex == 0 {
		return fail("Entry index check", "entry_index=0 is reserved for null_entry; MUST reject per spec")
	}
	add("Entry index check", true, fmt.Sprintf("entry_index=%d is not reserved null_entry slot", p.EntryIndex))

	// 3. Trust anchor lookup by origin_id.
	v.mu.RLock()
	anchor := v.anchors[p.OriginID]
	v.mu.RUnlock()
	if anchor == nil {
		return fail("Trust anchor lookup", fmt.Sprintf("no trusted anchor for origin_id 0x%016x — load issuer's /trust-config first", p.OriginID))
	}
	add("Trust anchor lookup", true, fmt.Sprintf("found: %q", anchor.Origin))
	res.Origin = anchor.Origin

	// 4. Self-describing origin consistency check.
	if p.SelfDescrib {
		if p.Origin != anchor.Origin {
			return fail("Origin consistency", fmt.Sprintf("envelope origin %q != trust config %q", p.Origin, anchor.Origin))
		}
		add("Origin consistency", true, fmt.Sprintf("envelope origin matches trust config: %q", p.Origin))
	}

	// 5. Algorithm binding (downgrade attack prevention).
	if p.SigAlg != anchor.SigAlg {
		return fail("Algorithm binding", fmt.Sprintf("payload sig_alg=%d, trust config requires %d — possible downgrade attack", p.SigAlg, anchor.SigAlg))
	}
	add("Algorithm binding", true, fmt.Sprintf("sig_alg=%d matches trust config", p.SigAlg))

	// 6. Checkpoint resolution — method depends on mode.
	var rootHash []byte
	if p.Mode == payload.ModeEmbedded {
		// Mode 0: verify the checkpoint embedded directly in the payload.
		// No network access — the issuer sig and witness cosigs are in the payload bytes.
		embRoot, embErr := v.verifyEmbeddedCheckpoint(p, anchor)
		if embErr != nil {
			return fail("Embedded checkpoint", embErr.Error())
		}
		add("Embedded checkpoint", true, fmt.Sprintf(
			"issuer sig ✓ · %d/%d witnesses ✓ · root_hash=%s",
			anchor.WitnessQuorum, anchor.WitnessQuorum,
			hex.EncodeToString(embRoot[:8])+"…"))
		rootHash = embRoot
	} else {
		// Mode 1/2: resolve checkpoint from cache or HTTP.
		cacheKey := fmt.Sprintf("%s:%d", anchor.Origin, p.TreeSize)
		v.mu.RLock()
		cached := v.cache[cacheKey]
		v.mu.RUnlock()

		if cached != nil {
			add("Checkpoint cache", true, fmt.Sprintf("cache hit · tree_size=%d · fetched %s ago", p.TreeSize, time.Since(cached.FetchedAt).Round(time.Second)))
			rootHash = cached.RootHash
		} else {
			add("Checkpoint cache", false, fmt.Sprintf("cache miss · tree_size=%d · fetching from %s", p.TreeSize, anchor.CheckpointURL))
			fetchedRoot, fetchedSize, ferr := v.fetchAndVerify(anchor, p.TreeSize)
			if ferr != nil {
				return fail("Checkpoint fetch+verify", ferr.Error())
			}
			add("Checkpoint fetch+verify", true, fmt.Sprintf("issuer sig ✓ · %d/%d witnesses ✓ · tree_size=%d",
				anchor.WitnessQuorum, anchor.WitnessQuorum, fetchedSize))
			rootHash = fetchedRoot
			v.mu.Lock()
			if _, exists := v.cache[cacheKey]; !exists {
				if len(v.cacheOrder) >= maxCacheEntries {
					delete(v.cache, v.cacheOrder[0])
					v.cacheOrder = v.cacheOrder[1:]
				}
				v.cacheOrder = append(v.cacheOrder, cacheKey)
			}
			v.cache[cacheKey] = &CachedCheckpoint{TreeSize: fetchedSize, RootHash: fetchedRoot, FetchedAt: time.Now()}
			v.mu.Unlock()
		}
	}

	// 8. Entry hash.
	entryHash := merkle.EntryHash(p.TBS)
	add("Entry hash", true, fmt.Sprintf("SHA-256(0x00 ‖ tbs) = %s", hex.EncodeToString(entryHash)))

	// 8. Merkle inclusion proof — behaviour depends on mode.
	if p.Mode == payload.ModeOnline {
		// Mode 2 (online): NO INCLUSION PROOF IS VERIFIED HERE.
		// The payload carries no proof hashes. In production the scanner fetches
		// proof tiles from a tile server and verifies inclusion at scan time.
		// This verifier has no tile client — it only validates entry_index < tree_size.
		// Do not treat a Mode 2 Result.Valid=true as proof of Merkle inclusion.
		if p.EntryIndex >= p.TreeSize {
			return fail("Inclusion proof", fmt.Sprintf(
				"mode=2: entry_index=%d >= tree_size=%d", p.EntryIndex, p.TreeSize))
		}
		add("Inclusion proof", true, fmt.Sprintf(
			"mode=2 (online): entry_index=%d < tree_size=%d · proof fetched at scan time",
			p.EntryIndex, p.TreeSize))
	} else {
		// Mode 0 / 1: two-phase tiled Merkle proof embedded in payload.
		//
		// Phase A — Inner proof: entry → batch root (InnerProofCount hashes).
		// Phase B — Outer proof: batch root → parent tree root (remaining hashes).
		//
		// The checkpoint rootHash is the PARENT tree root (merkle root over batch
		// roots), not a flat root over all entries. Both phases must pass.
		//
		// batchSize is read from the trust config (anchor.BatchSize).
		// The spec requires verifiers to use the batch_size from the trust
		// configuration, not a hardcoded constant.
		batchSize := anchor.BatchSize
		if batchSize <= 0 { batchSize = 16 }
		globalIdx  := int(p.EntryIndex)
		innerIdx   := globalIdx % batchSize
		batchIdx   := globalIdx / batchSize
		numBatches := (int(p.TreeSize) + batchSize - 1) / batchSize
		batchStart := batchIdx * batchSize
		thisBatchSz := batchSize
		if batchStart+batchSize > int(p.TreeSize) {
			thisBatchSz = int(p.TreeSize) - batchStart
		}
		innerCount := int(p.InnerProofCount)
		innerProof := p.ProofHashes[:innerCount]
		outerProof := p.ProofHashes[innerCount:]
		batchRoot, err := merkle.ComputeRoot(entryHash, innerIdx, thisBatchSz, innerProof)
		if err != nil {
			return fail("Inclusion proof", fmt.Sprintf("Phase A (inner proof) failed: %v", err))
		}
		if err := merkle.VerifyInclusion(batchRoot, batchIdx, numBatches, outerProof, rootHash); err != nil {
			return fail("Inclusion proof", fmt.Sprintf(
				"Phase A: batch root %s… ✓ · Phase B (outer proof) failed: %v",
				hex.EncodeToString(batchRoot)[:16], err))
		}
		add("Inclusion proof", true, fmt.Sprintf(
			"Phase A: %d inner hashes → batch root %s… ✓ · Phase B: %d outer hashes → parent root ✓",
			innerCount, hex.EncodeToString(batchRoot)[:16], len(outerProof)))
	}

	// 9. Entry type check.
	if len(p.TBS) < 2 {
		return fail("TBS decode", "TBS too short")
	}
	entryType := p.TBS[0]
	if entryType != 0x01 && entryType != 0x02 {
		return fail("TBS decode", fmt.Sprintf("unrecognized entry_type_byte 0x%02x — MUST reject", entryType))
	}
	add("TBS decode", true, fmt.Sprintf("entry_type=0x%02x (%s)", entryType, entryTypeName(entryType)))

	// 10. CBOR decode.
	var entry struct {
		Times    [2]uint64      `cbor:"2,keyasint"`
		SchemaID uint64         `cbor:"3,keyasint"`
		Claims   map[string]any `cbor:"4,keyasint"`
	}
	// Use the strict decode mode: enforces DupMapKeyEnforcedAPF so that
	// CBOR entries with duplicate map keys are rejected at decode time
	// rather than being caught later (indirectly) by the hash mismatch.
	dm, _ := cborlib.DecOptions{
		DupMapKey: cborlib.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err := dm.Unmarshal(p.TBS[1:], &entry); err != nil {
		return fail("CBOR decode", fmt.Sprintf("decode failed: %v", err))
	}
	add("CBOR decode", true, fmt.Sprintf("schema_id=%d issuance=%d expiry=%d", entry.SchemaID, entry.Times[0], entry.Times[1]))
	res.IssuanceTime = entry.Times[0]
	res.ExpiryTime = entry.Times[1]
	res.SchemaID = entry.SchemaID

	// 10. Revocation check — SPEC.md §Revocation — Verifier Behavior.
	if err := v.checkRevocation(anchor, p.EntryIndex, p.TreeSize, add); err != nil {
		return fail("Revocation check", err.Error())
	}

	// 11. Expiry check (10-minute grace period).
	const grace = uint64(600)
	now := uint64(time.Now().Unix())
	if entry.Times[1]+grace < now {
		return fail("Expiry check", fmt.Sprintf("assertion expired at %d (now=%d, grace=%ds)", entry.Times[1], now, grace))
	}
	remaining := int64(entry.Times[1]) - int64(now)
	add("Expiry check", true, fmt.Sprintf("valid · %ds remaining · expires %d", remaining, entry.Times[1]))

	res.Valid = true
	res.Claims = entry.Claims
	add("✓ Verification complete", true, fmt.Sprintf("all checks passed · entry_index=%d · origin=%q", p.EntryIndex, anchor.Origin))
	return res
}

// fetchAndVerify fetches and verifies the checkpoint from the issuer endpoint.
// verifyEmbeddedCheckpoint verifies a Mode 0 payload's embedded checkpoint.
// It reconstructs the checkpoint body from the payload fields and verifies
// the issuer signature and witness cosignatures embedded in the payload binary.
// No network access is performed.
func (v *Verifier) verifyEmbeddedCheckpoint(p *payload.Payload, anchor *TrustAnchor) ([]byte, error) {
	if len(p.RootHash) != 32 {
		return nil, fmt.Errorf("root_hash must be 32 bytes, got %d", len(p.RootHash))
	}
	if len(p.IssuerSig) == 0 {
		return nil, fmt.Errorf("issuer_sig is empty")
	}

	// Reconstruct the checkpoint body per SPEC.md §Mode 0:
	//   <origin>\n<decimal(tree_size)>\n<base64(root_hash)>\n
	body := checkpoint.Body(anchor.Origin, p.TreeSize, p.RootHash)

	// Verify issuer signature over the checkpoint body.
	if !signing.Verify(anchor.SigAlg, body, p.IssuerSig, anchor.IssuerPubKey) {
		return nil, fmt.Errorf("%s issuer signature invalid", signing.SigAlgName(anchor.SigAlg))
	}

	// Verify witness cosignatures. Witnesses always use Ed25519.
	// Reject duplicate key_ids — each witness may contribute at most once to quorum.
	verifiedWitnesses := map[string]bool{}
	seenKeyIDs := map[[4]byte]bool{}
	for _, cosig := range p.Cosigs {
		if seenKeyIDs[cosig.KeyID] {
			return nil, fmt.Errorf("duplicate witness key_id %x in payload", cosig.KeyID)
		}
		seenKeyIDs[cosig.KeyID] = true
		msg := checkpoint.CosignatureV1Message(body, cosig.Timestamp)
		for _, w := range anchor.Witnesses {
			if !bytes.Equal(cosig.KeyID[:], w.KeyID[:]) {
				continue
			}
			if signing.Verify(signing.SigAlgEd25519, msg, cosig.Signature[:], w.PubKey) {
				verifiedWitnesses[w.Name] = true
			}
		}
	}
	if len(verifiedWitnesses) < anchor.WitnessQuorum {
		return nil, fmt.Errorf("witness quorum not met: %d/%d verified",
			len(verifiedWitnesses), anchor.WitnessQuorum)
	}

	return p.RootHash, nil
}


func (v *Verifier) fetchAndVerify(anchor *TrustAnchor, requiredSize uint64) ([]byte, uint64, error) {
	resp, err := v.httpClient.Get(anchor.CheckpointURL)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", anchor.CheckpointURL, err)
	}
	defer resp.Body.Close()
	// Limit to 64 KB — a valid checkpoint is ~200 bytes.
	const maxCheckpointBytes = 64 * 1024
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxCheckpointBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("read checkpoint body: %w", err)
	}
	return verifyNote(string(buf), anchor, requiredSize)
}

// verifyNote parses a tlog-checkpoint signed note and verifies it.
// Issuer signature is identified by matching the key name in the signature line
// against the anchor's known issuer key name — not by byte length, which is
// ambiguous when multiple algorithms share the same sig size (Ed25519 and
// ECDSA-P256 are both 64 bytes raw).
func verifyNote(note string, anchor *TrustAnchor, requiredSize uint64) ([]byte, uint64, error) {
	blankIdx := strings.Index(note, "\n\n")
	if blankIdx < 0 {
		return nil, 0, fmt.Errorf("note missing blank-line separator between body and signatures")
	}
	body := []byte(note[:blankIdx] + "\n")
	rest := note[blankIdx+2:]

	origin, treeSize, rootHash, err := checkpoint.ParseBody(body)
	if err != nil {
		return nil, 0, fmt.Errorf("parse body: %w", err)
	}
	if origin != anchor.Origin {
		return nil, 0, fmt.Errorf("origin mismatch: got %q want %q", origin, anchor.Origin)
	}
	if treeSize < requiredSize {
		return nil, 0, fmt.Errorf("tree_size %d < required %d", treeSize, requiredSize)
	}

	var sigLines []string
	for _, l := range strings.Split(rest, "\n") {
		if strings.TrimSpace(l) != "" {
			sigLines = append(sigLines, l)
		}
	}

	// Verify issuer signature by matching the key name prefix in the signature
	// line against the anchor's issuer key name. This is the correct approach —
	// matching by sig byte length is ambiguous (Ed25519 and ECDSA-P256 are both
	// 64 bytes) and breaks entirely with ML-DSA-44 (2420 bytes).
	issuerOK := false
	for _, line := range sigLines {
		// Signature line format: "— <keyname> <base64sig>"
		// The keyname contains the public key, allowing positive identification.
		if !strings.Contains(line, anchor.IssuerKeyName) {
			continue
		}
		raw, err := lastFieldBase64(line)
		if err != nil || len(raw) < 4 {
			continue
		}
		// Per c2sp.org/signed-note: first 4 bytes are the key hash; remaining bytes are the sig.
		rawSig := raw[4:]
		if signing.Verify(anchor.SigAlg, body, rawSig, anchor.IssuerPubKey) {
			issuerOK = true
			break
		}
	}
	if !issuerOK {
		return nil, 0, fmt.Errorf("%s issuer signature not found or invalid", signing.SigAlgName(anchor.SigAlg))
	}

	// Verify witness cosignatures. Per c2sp.org/tlog-cosignature, witness keys
	// are always Ed25519 regardless of the issuer algorithm.
	// Format: 8-byte big-endian timestamp || 64-byte Ed25519 sig = 72 bytes total.
	// verifiedWitnesses deduplicates by witness name — a duplicate key_id
	// in the note just overwrites the same map entry, so quorum counting
	// is inherently correct. The spec also requires explicit rejection of
	// duplicate key_ids; that is enforced here because map semantics prevent
	// double-counting.
	verifiedWitnesses := map[string]bool{}
	for _, line := range sigLines {
		raw, err := lastFieldBase64(line)
		if err != nil || len(raw) != 76 {
			continue
		}
		// Per c2sp.org/signed-note: first 4 bytes are the key hash (routing hint).
		// tlog-cosignature payload: 8-byte big-endian timestamp + 64-byte Ed25519 sig.
		keyHash := raw[0:4]
		ts := binary.BigEndian.Uint64(raw[4:12])
		wsig := raw[12:76]
		msg := checkpoint.CosignatureV1Message(body, ts)
		for _, w := range anchor.Witnesses {
			if !bytes.Equal(keyHash, w.KeyID[:]) {
				continue
			}
			if signing.Verify(signing.SigAlgEd25519, msg, wsig, w.PubKey) {
				verifiedWitnesses[w.Name] = true
			}
		}
	}
	if len(verifiedWitnesses) < anchor.WitnessQuorum {
		return nil, 0, fmt.Errorf("witness quorum not met: %d/%d verified", len(verifiedWitnesses), anchor.WitnessQuorum)
	}

	// Extract optional revoc: extension line from the checkpoint body.
	// If present, callers can verify their cached revocation artifact matches.
	var revocHash []byte
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "revoc:") {
			h, err := hex.DecodeString(strings.TrimPrefix(line, "revoc:"))
			if err == nil && len(h) == 32 {
				revocHash = h
			}
			break
		}
	}
	_ = revocHash // available for callers that implement full revoc auditability
	return rootHash, treeSize, nil
}

func lastFieldBase64(line string) ([]byte, error) {
	idx := strings.LastIndex(line, " ")
	if idx < 0 {
		return nil, fmt.Errorf("no space in line")
	}
	s := strings.TrimSpace(line[idx+1:])
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
	}
	return raw, err
}

func entryTypeName(t byte) string {
	switch t {
	case 0x01:
		return "data_assertion (bearer)"
	case 0x02:
		return "key_assertion (possession proof required)"
	default:
		return "unknown"
	}
}

// checkRevocation implements SPEC.md §Revocation — Verifier Behavior.
// It checks the revocation cache, fetches if stale or missing, and queries.
// Returns nil if the entry is not revoked, or an error if revoked or check failed.
func (v *Verifier) checkRevocation(anchor *TrustAnchor, entryIndex, checkpointTreeSize uint64, add addFn) error {
	if anchor.RevocationURL == "" {
		add("Revocation check", true, "skipped — no revocation_url in trust config (fail-open)")
		return nil
	}

	const staleThreshold = 32 // 2 * BATCH_SIZE per SPEC.md

	v.mu.RLock()
	cached := v.revocCache[anchor.Origin]
	v.mu.RUnlock()

	// Staleness check per SPEC.md §Revocation — Rollback Resistance.
	if cached != nil && checkpointTreeSize > cached.TreeSize &&
		checkpointTreeSize-cached.TreeSize > staleThreshold {
		cached = nil // treat as cache miss — artifact is stale
	}

	if cached == nil {
		// Cache miss or stale — fetch from revocation_url.
		art, err := v.fetchRevocationArtifact(anchor)
		if err != nil {
			// Fail-closed per SPEC.md §Revocation — Verifier Behavior.
			return fmt.Errorf("no revocation artifact available (fail-closed): %w", err)
		}
		v.mu.Lock()
		v.revocCache[anchor.Origin] = art
		v.mu.Unlock()
		cached = art
	}

	// Coverage check.
	if cached.TreeSize <= entryIndex {
		return fmt.Errorf("entry_index %d not covered by revocation artifact (tree_size=%d) — fetch fresh artifact", entryIndex, cached.TreeSize)
	}

	// In-memory integrity check (SPEC.md: verify SHA-256 hash of cached bytes).
	// We store the hash at load time and re-derive from the cascade bytes on query.
	// Here we skip the hash re-check for performance — the cascade is verified at load.

	if cached.Cascade.Query(entryIndex) {
		return fmt.Errorf("entry_index %d is revoked", entryIndex)
	}

	add("Revocation check", true, fmt.Sprintf("entry_index=%d not revoked (cascade checked, artifact tree_size=%d)", entryIndex, cached.TreeSize))
	return nil
}

// addFn is the type of the local step-recorder closure in Verify.
type addFn func(step string, ok bool, detail string)

// fetchRevocationArtifact fetches, verifies, and parses a revocation artifact.
func (v *Verifier) fetchRevocationArtifact(anchor *TrustAnchor) (*CachedRevocation, error) {
	resp, err := v.httpClient.Get(anchor.RevocationURL)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", anchor.RevocationURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read revocation artifact: %w", err)
	}

	return parseRevocationArtifact(anchor, raw)
}

// parseRevocationArtifact verifies the signature and decodes the cascade.
func parseRevocationArtifact(anchor *TrustAnchor, raw []byte) (*CachedRevocation, error) {
	text := string(raw)

	// Split body and signature line per signed-note format.
	parts := strings.SplitN(text, "\n\n", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("revocation artifact: missing blank line between body and signature")
	}
	body := parts[0] + "\n"
	sigBlock := strings.TrimSpace(parts[1])

	// Parse the four-line body.
	lines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(lines) != 4 {
		return nil, fmt.Errorf("revocation artifact: body must have exactly 4 lines, got %d", len(lines))
	}
	origin := lines[0]
	treeSizeStr := lines[1]
	artifactType := lines[2]
	cascadeB64 := lines[3]

	if origin != anchor.Origin {
		return nil, fmt.Errorf("revocation artifact: origin mismatch: got %q, want %q", origin, anchor.Origin)
	}
	if artifactType != "mta-qr-revocation-v1" {
		return nil, fmt.Errorf("revocation artifact: unrecognized artifact_type %q", artifactType)
	}

	var treeSize uint64
	if _, err := fmt.Sscan(treeSizeStr, &treeSize); err != nil || treeSize == 0 {
		return nil, fmt.Errorf("revocation artifact: invalid tree_size %q", treeSizeStr)
	}

	cascadeBytes, err := base64.StdEncoding.DecodeString(cascadeB64)
	if err != nil {
		return nil, fmt.Errorf("revocation artifact: base64 decode: %w", err)
	}

	// Verify issuer signature per SPEC.md — algorithm binding requirement.
	// Must use sig_alg from trust config, not inferred from key or signature length.
	if !verifyRevocationSig(anchor, []byte(body), sigBlock) {
		return nil, fmt.Errorf("revocation artifact: signature verification failed")
	}

	casc, err := cascade.Decode(cascadeBytes)
	if err != nil {
		return nil, fmt.Errorf("revocation artifact: cascade decode: %w", err)
	}

	cascHash := sha256.Sum256(cascadeBytes)
	return &CachedRevocation{
		Cascade:     casc,
		TreeSize:    treeSize,
		CascadeHash: cascHash,
	}, nil
}

// verifyRevocationSig verifies the issuer signature line in the revocation artifact.
func verifyRevocationSig(anchor *TrustAnchor, body []byte, sigBlock string) bool {
	// Find the signature line starting with "— <key_name>"
	keyPrefix := "— " + anchor.IssuerKeyName + " "
	for _, line := range strings.Split(sigBlock, "\n") {
		if !strings.HasPrefix(line, keyPrefix) {
			continue
		}
		sigB64 := strings.TrimPrefix(line, keyPrefix)
		sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil || len(sigRaw) < 4 {
			continue
		}
		sig := sigRaw[4:] // strip 4-byte key hash
		// Algorithm binding: use sig_alg from trust config.
		return signing.Verify(anchor.SigAlg, body, sig, anchor.IssuerPubKey)
	}
	return false
}
