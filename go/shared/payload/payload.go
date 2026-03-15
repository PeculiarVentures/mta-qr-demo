// Package payload implements MTAQRPayload binary encoding and decoding.
// Binary format is big-endian. All length fields are bounds-checked before
// any variable-length field is read.
package payload

import (
	"encoding/binary"
	"fmt"
)

// Mode constants.
const (
	ModeEmbedded = 0 // Mode 0: fully offline, checkpoint embedded in payload
	ModeCached   = 1 // Mode 1: checkpoint fetched/cached at charge time
	ModeOnline   = 2 // Mode 2: inclusion proof fetched at scan time
)

// SigAlg constants.
const (
	SigAlgFNDSA512   = 0
	SigAlgMLDSA44    = 1
	SigAlgMLDSA65    = 2
	SigAlgSLHDSA128s = 3
	SigAlgECDSAP256  = 4
	SigAlgECDSAP384  = 5
	SigAlgEd25519    = 6
)

// WitnessCosig is a single witness cosignature in a Mode 0 payload.
// Total: 76 bytes (4 key_id + 8 timestamp + 64 signature).
type WitnessCosig struct {
	KeyID     [4]byte  // 4-byte witness key ID
	Timestamp uint64   // Unix seconds, big-endian uint64
	Signature [64]byte // Ed25519 signature over cosignature/v1 message
}

// Payload is a decoded MTAQRPayload.
type Payload struct {
	Version     uint8
	Mode        uint8
	SigAlg      uint8
	DualSig     bool
	SelfDescrib bool

	OriginID   uint64
	TreeSize   uint64
	EntryIndex uint64

	// Self-describing mode only.
	Origin string

	// Inclusion proof (Mode 0 and 1 only; empty for Mode 2).
	// ProofHashes = InnerProofHashes ++ OuterProofHashes.
	// InnerProofCount tells the verifier where the split is.
	//
	// Inner proof: entry_hash → batch root (≤ BATCH_LOG2 hashes).
	// Outer proof: batch root → parent tree root (≤ BATCH_LOG2 hashes).
	//
	// Both the issuer sign and the checkpoint tree_size reference the
	// total entry count; rootHash in the checkpoint is the PARENT tree root
	// (merkle root of batch roots), not a flat root over all entries.
	ProofHashes      [][]byte // each element is 32 bytes
	InnerProofCount  uint8    // how many leading ProofHashes are the inner proof

	// The authenticated entry: entry_type_byte || CBOR(AssertionLogEntry).
	TBS []byte

	// Mode 0 only — embedded checkpoint.
	RootHash  []byte
	IssuerSig []byte
	Cosigs    []WitnessCosig
}

// Encode serializes a Payload to its binary wire format.
func Encode(p *Payload) ([]byte, error) {
	if err := validate(p); err != nil {
		return nil, err
	}

	var buf []byte
	// version
	buf = append(buf, p.Version)
	// flags byte
	flags := p.Mode & 0x03
	flags |= (p.SigAlg & 0x07) << 2
	if p.DualSig {
		flags |= 0x20
	}
	if p.SelfDescrib {
		flags |= 0x80
	}
	buf = append(buf, flags)
	// origin_id (8 bytes big-endian)
	buf = appendUint64(buf, p.OriginID)
	// tree_size (8 bytes big-endian)
	buf = appendUint64(buf, p.TreeSize)
	// entry_index (8 bytes big-endian)
	buf = appendUint64(buf, p.EntryIndex)

	// Self-describing: origin_len (2 bytes) + origin bytes
	if p.SelfDescrib {
		originBytes := []byte(p.Origin)
		buf = appendUint16(buf, uint16(len(originBytes)))
		buf = append(buf, originBytes...)
	}

	// proof_count (1 byte) + inner_proof_count (1 byte) + proof bytes
	buf = append(buf, uint8(len(p.ProofHashes)))
	buf = append(buf, p.InnerProofCount)
	for _, h := range p.ProofHashes {
		buf = append(buf, h...)
	}

	// tbs_len (2 bytes) + tbs bytes
	buf = appendUint16(buf, uint16(len(p.TBS)))
	buf = append(buf, p.TBS...)

	// Mode 0 only: embedded checkpoint
	if p.Mode == ModeEmbedded {
		buf = append(buf, p.RootHash...)
		buf = appendUint16(buf, uint16(len(p.IssuerSig)))
		buf = append(buf, p.IssuerSig...)
		buf = append(buf, uint8(len(p.Cosigs)))
		for _, c := range p.Cosigs {
			buf = append(buf, c.KeyID[:]...)
			buf = appendUint64(buf, c.Timestamp)
			buf = append(buf, c.Signature[:]...)
		}
	}

	return buf, nil
}

// Decode parses a binary payload. All length fields are bounds-checked before
// any variable-length read. Returns an error on any malformed input.
func Decode(data []byte) (*Payload, error) {
	r := &reader{data: data, pos: 0}
	p := &Payload{}

	v, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("payload: read version: %w", err)
	}
	if v != 0x01 {
		return nil, fmt.Errorf("payload: unsupported version 0x%02x", v)
	}
	p.Version = v

	flags, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("payload: read flags: %w", err)
	}
	p.Mode = flags & 0x03
	p.SigAlg = (flags >> 2) & 0x07
	p.DualSig = (flags & 0x20) != 0
	p.SelfDescrib = (flags & 0x80) != 0

	if p.Mode > 2 {
		return nil, fmt.Errorf("payload: invalid mode %d", p.Mode)
	}
	if p.SigAlg > 6 {
		return nil, fmt.Errorf("payload: unrecognized sig_alg %d", p.SigAlg)
	}

	p.OriginID, err = r.readUint64()
	if err != nil {
		return nil, fmt.Errorf("payload: read origin_id: %w", err)
	}
	p.TreeSize, err = r.readUint64()
	if err != nil {
		return nil, fmt.Errorf("payload: read tree_size: %w", err)
	}
	p.EntryIndex, err = r.readUint64()
	if err != nil {
		return nil, fmt.Errorf("payload: read entry_index: %w", err)
	}

	if p.SelfDescrib {
		originLen, err := r.readUint16()
		if err != nil {
			return nil, fmt.Errorf("payload: read origin_len: %w", err)
		}
		originBytes, err := r.readBytes(int(originLen))
		if err != nil {
			return nil, fmt.Errorf("payload: read origin: %w", err)
		}
		p.Origin = string(originBytes)
	}

	numProof, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("payload: read proof_count: %w", err)
	}
	// Bound proof_count to prevent DoS via allocation of up to 255×32=8160 bytes
	// for a bogus payload. The two-level tiled proof needs at most ~10 hashes in
	// practice; 64 gives ample headroom for any valid tree depth.
	const maxProofHashes = 64
	if numProof > maxProofHashes {
		return nil, fmt.Errorf("payload: proof_count %d exceeds maximum %d", numProof, maxProofHashes)
	}
	if p.Mode == ModeOnline && numProof != 0 {
		return nil, fmt.Errorf("payload: Mode 2 must have proof_count=0, got %d", numProof)
	}
	innerProofCount, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("payload: read inner_proof_count: %w", err)
	}
	if innerProofCount > numProof {
		return nil, fmt.Errorf("payload: inner_proof_count(%d) > proof_count(%d)", innerProofCount, numProof)
	}
	p.InnerProofCount = innerProofCount
	p.ProofHashes = make([][]byte, numProof)
	for i := range p.ProofHashes {
		h, err := r.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("payload: read proof hash %d: %w", i, err)
		}
		p.ProofHashes[i] = h
	}

	tbsLen, err := r.readUint16()
	if err != nil {
		return nil, fmt.Errorf("payload: read tbs_len: %w", err)
	}
	if tbsLen == 0 {
		return nil, fmt.Errorf("payload: tbs_len must be >= 1")
	}
	p.TBS, err = r.readBytes(int(tbsLen))
	if err != nil {
		return nil, fmt.Errorf("payload: read tbs: %w", err)
	}

	if p.Mode == ModeEmbedded {
		p.RootHash, err = r.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("payload: read root_hash: %w", err)
		}
		sigLen, err := r.readUint16()
		if err != nil {
			return nil, fmt.Errorf("payload: read issuer_sig_len: %w", err)
		}
		p.IssuerSig, err = r.readBytes(int(sigLen))
		if err != nil {
			return nil, fmt.Errorf("payload: read issuer_sig: %w", err)
		}
		cosigCount, err := r.readByte()
		if err != nil {
			return nil, fmt.Errorf("payload: read witness_count: %w", err)
		}
		p.Cosigs = make([]WitnessCosig, cosigCount)
		for i := range p.Cosigs {
			kid, err := r.readBytes(4)
			if err != nil {
				return nil, fmt.Errorf("payload: read cosig[%d] key_id: %w", i, err)
			}
			copy(p.Cosigs[i].KeyID[:], kid)
			p.Cosigs[i].Timestamp, err = r.readUint64()
			if err != nil {
				return nil, fmt.Errorf("payload: read cosig[%d] timestamp: %w", i, err)
			}
			sig, err := r.readBytes(64)
			if err != nil {
				return nil, fmt.Errorf("payload: read cosig[%d] signature: %w", i, err)
			}
			copy(p.Cosigs[i].Signature[:], sig)
		}
	}

	if r.pos != len(r.data) {
		return nil, fmt.Errorf("payload: %d trailing bytes after end of payload", len(r.data)-r.pos)
	}

	return p, nil
}

func validate(p *Payload) error {
	if p.Version != 0x01 {
		return fmt.Errorf("payload: version must be 0x01")
	}
	if p.Mode > 2 {
		return fmt.Errorf("payload: invalid mode %d", p.Mode)
	}
	if p.SigAlg > 6 {
		return fmt.Errorf("payload: unrecognized sig_alg %d", p.SigAlg)
	}
	if len(p.TBS) == 0 {
		return fmt.Errorf("payload: tbs must not be empty")
	}
	if p.Mode == ModeOnline && len(p.ProofHashes) != 0 {
		return fmt.Errorf("payload: Mode 2 must have empty proofHashes (proof_count must be 0)")
	}
	if p.Mode == ModeEmbedded {
		if len(p.RootHash) != 32 {
			return fmt.Errorf("payload: root_hash must be 32 bytes")
		}
	}
	return nil
}

// --- helpers ---

type reader struct {
	data []byte
	pos  int
}

func (r *reader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("unexpected end of payload at offset %d", r.pos)
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("need %d bytes at offset %d, only %d remaining", n, r.pos, len(r.data)-r.pos)
	}
	b := make([]byte, n)
	copy(b, r.data[r.pos:r.pos+n])
	r.pos += n
	return b, nil
}

func (r *reader) readUint16() (uint16, error) {
	b, err := r.readBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *reader) readUint64() (uint64, error) {
	b, err := r.readBytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}
