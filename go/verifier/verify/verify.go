// Package verify implements the MTA-QR Mode 1 verification flow.
package verify

import (
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
	"github.com/mta-qr/demo/shared/checkpoint"
	"github.com/mta-qr/demo/shared/signing"
	"github.com/mta-qr/demo/shared/merkle"
	"github.com/mta-qr/demo/shared/payload"
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

// Verifier holds trust anchors and a checkpoint cache.
type Verifier struct {
	mu         sync.RWMutex
	anchors    map[uint64]*TrustAnchor
	cache      map[string]*CachedCheckpoint
	cacheOrder []string // insertion order for LRU eviction
}

// New creates an empty Verifier.
func New() *Verifier {
	return &Verifier{
		anchors:    make(map[uint64]*TrustAnchor),
		cache:      make(map[string]*CachedCheckpoint),
		cacheOrder: make([]string, 0, maxCacheEntries+1),
	}
}

// AddAnchor registers a trusted issuer.
func (v *Verifier) AddAnchor(a *TrustAnchor) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.anchors[a.OriginID] = a
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

	// 6. Checkpoint resolution.
	cacheKey := fmt.Sprintf("%s:%d", anchor.Origin, p.TreeSize)
	v.mu.RLock()
	cached := v.cache[cacheKey]
	v.mu.RUnlock()

	var rootHash []byte
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

	// 7. Entry hash.
	entryHash := merkle.EntryHash(p.TBS)
	add("Entry hash", true, fmt.Sprintf("SHA-256(0x00 ‖ tbs) = %s", hex.EncodeToString(entryHash)))

	// 8. Two-phase tiled Merkle inclusion proof.
	//
	// Phase A — Inner proof: entry → batch root (InnerProofCount hashes).
	// Phase B — Outer proof: batch root → parent tree root (remaining hashes).
	//
	// The checkpoint rootHash is the PARENT tree root (merkle root over batch
	// roots), not a flat root over all entries. Both phases must pass.
	//
	// batchSize matches log.BatchSize (16). Defined as a local constant to
	// avoid importing the issuer/log package from the verifier.
	const batchSize  = 16 // must match log.BatchSize
	globalIdx    := int(p.EntryIndex)
	innerIdx     := globalIdx % batchSize
	batchIdx     := globalIdx / batchSize
	numBatches   := (int(p.TreeSize) + batchSize - 1) / batchSize
	batchStart   := batchIdx * batchSize
	thisBatchSz  := batchSize
	if batchStart+batchSize > int(p.TreeSize) {
		thisBatchSz = int(p.TreeSize) - batchStart
	}

	innerCount := int(p.InnerProofCount)
	innerProof := p.ProofHashes[:innerCount]
	outerProof := p.ProofHashes[innerCount:]

	// Phase A: recompute batch root from entry hash + inner proof.
	batchRoot, err := merkle.ComputeRoot(entryHash, innerIdx, thisBatchSz, innerProof)
	if err != nil {
		return fail("Inclusion proof", fmt.Sprintf("Phase A (inner proof) failed: %v", err))
	}

	// Phase B: verify batch root in parent tree.
	if err := merkle.VerifyInclusion(batchRoot, batchIdx, numBatches, outerProof, rootHash); err != nil {
		return fail("Inclusion proof", fmt.Sprintf(
			"Phase A: batch root %s… ✓ · Phase B (outer proof) failed: %v",
			hex.EncodeToString(batchRoot)[:16], err))
	}
	add("Inclusion proof", true, fmt.Sprintf(
		"Phase A: %d inner hashes → batch root %s… ✓ · Phase B: %d outer hashes → parent root ✓",
		innerCount, hex.EncodeToString(batchRoot)[:16], len(outerProof)))

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
	dm, _ := cborlib.DecOptions{}.DecMode()
	if err := dm.Unmarshal(p.TBS[1:], &entry); err != nil {
		return fail("CBOR decode", fmt.Sprintf("decode failed: %v", err))
	}
	add("CBOR decode", true, fmt.Sprintf("schema_id=%d issuance=%d expiry=%d", entry.SchemaID, entry.Times[0], entry.Times[1]))
	res.IssuanceTime = entry.Times[0]
	res.ExpiryTime = entry.Times[1]
	res.SchemaID = entry.SchemaID

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
func (v *Verifier) fetchAndVerify(anchor *TrustAnchor, requiredSize uint64) ([]byte, uint64, error) {
	resp, err := http.Get(anchor.CheckpointURL)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", anchor.CheckpointURL, err)
	}
	defer resp.Body.Close()
	// io.ReadAll — a single Read() call is not guaranteed to return all bytes.
	buf, err := io.ReadAll(resp.Body)
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
		if err != nil {
			continue
		}
		if signing.Verify(anchor.SigAlg, body, raw, anchor.IssuerPubKey) {
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
	verifiedWitnesses := map[string]bool{}
	for _, line := range sigLines {
		raw, err := lastFieldBase64(line)
		if err != nil || len(raw) != 72 {
			continue
		}
		ts := binary.BigEndian.Uint64(raw[:8])
		wsig := raw[8:72]
		msg := checkpoint.CosignatureV1Message(body, ts)
		for _, w := range anchor.Witnesses {
			if signing.Verify(signing.SigAlgEd25519, msg, wsig, w.PubKey) {
				verifiedWitnesses[w.Name] = true
			}
		}
	}
	if len(verifiedWitnesses) < anchor.WitnessQuorum {
		return nil, 0, fmt.Errorf("witness quorum not met: %d/%d verified", len(verifiedWitnesses), anchor.WitnessQuorum)
	}

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
