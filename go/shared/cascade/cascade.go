// Package cascade implements the MTA-QR Bloom filter cascade for revocation.
//
// Wire format, construction parameters, and query algorithm are normatively
// defined in SPEC.md §Revocation — Normative Construction Parameters.
// All constants in this file MUST match the spec exactly.
package cascade

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// Construction constants — normative per SPEC.md §Revocation.
const (
	bitsPerElement = 1.4427 // = 1/ln(2); optimal for k=1 at ~50% FPR
	minFilterBits  = 8      // 1 byte minimum; preserves ~50% FPR for n=1
	maxLevels      = 32     // fail if cascade does not terminate by this depth
)

// Cascade is a Bloom filter cascade over a revoked/valid entry index set.
type Cascade struct {
	levels []level
}

type level struct {
	bitCount uint32
	bits     []byte // MSB-first: bit i is in byte i/8 at position 7-(i%8)
}

// bitPosition computes the bit index for element x at cascade level i.
// x is the entry_index encoded as 8-byte big-endian uint64.
// Per SPEC.md: bit_position(x, i) = big_endian_uint64(SHA-256(x || uint8(i))[0:8]) mod m
func bitPosition(x uint64, levelIdx int, m uint32) uint32 {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], x)
	buf[8] = byte(levelIdx)
	h := sha256.Sum256(buf[:])
	v := binary.BigEndian.Uint64(h[:8])
	return uint32(v % uint64(m))
}

// filterSize computes the bit array size for n elements.
// Per SPEC.md: m = max(ceil(n * 1.4427), 8) rounded up to byte boundary.
func filterSize(n int) uint32 {
	if n == 0 {
		return minFilterBits
	}
	m := int(float64(n)*bitsPerElement) + 1 // ceil via integer add
	if m < minFilterBits {
		m = minFilterBits
	}
	// Round up to byte boundary.
	return uint32((m + 7) &^ 7)
}

// Build constructs a Bloom filter cascade over (revoked, valid).
// Both slices contain entry_index values. The sets must be disjoint.
// Returns an empty cascade (num_levels=0) if revoked is empty.
func Build(revoked, valid []uint64) (*Cascade, error) {
	if len(revoked) == 0 {
		return &Cascade{}, nil
	}

	// Work with sorted copies to guarantee deterministic insertion order.
	include := sortedCopy(revoked) // Level 0: encode revoked indices
	exclude := sortedCopy(valid)   // Level 0: check valid indices for false positives

	var levels []level

	for levelIdx := 0; levelIdx < maxLevels; levelIdx++ {
		if len(include) == 0 {
			break
		}
		m := filterSize(len(include))
		bits := make([]byte, m/8)

		// Insert all elements of include into the filter.
		for _, x := range include {
			b := bitPosition(x, levelIdx, m)
			bits[b/8] |= 1 << (7 - b%8)
		}

		levels = append(levels, level{bitCount: m, bits: bits})

		// Find false positives: elements of exclude that hit this filter.
		var fp []uint64
		for _, x := range exclude {
			b := bitPosition(x, levelIdx, m)
			if bits[b/8]>>(7-b%8)&1 == 1 {
				fp = append(fp, x)
			}
		}

		// Swap domains: next level encodes false positives (to flip their answer)
		// and checks the previous include set for new false positives.
		include, exclude = fp, include
	}

	if len(include) != 0 {
		return nil, fmt.Errorf("cascade: did not terminate within %d levels — implementation or input error", maxLevels)
	}

	return &Cascade{levels: levels}, nil
}

// Query returns true if x is revoked, false if not revoked.
// False positives (valid entry reported revoked) are possible at the
// configured rate. False negatives (revoked entry reported valid) are
// impossible given a correctly built cascade.
func (c *Cascade) Query(x uint64) bool {
	if len(c.levels) == 0 {
		return false
	}
	result := false
	for i, lv := range c.levels {
		b := bitPosition(x, i, lv.bitCount)
		inFilter := lv.bits[b/8]>>(7-b%8)&1 == 1
		if i == 0 {
			if !inFilter {
				return false // definitely not revoked
			}
			result = true // tentatively revoked
		} else {
			if inFilter {
				result = !result // this level flips the answer (false positive caught)
			} else {
				return result // fell out: current interpretation is final
			}
		}
	}
	return result
}

// Encode serializes the cascade per SPEC.md §Revocation — Binary Encoding.
// Format: uint8 num_levels, then per level: uint32 bit_count | uint8 k=1 | bit_array.
func (c *Cascade) Encode() []byte {
	out := []byte{byte(len(c.levels))}
	for _, lv := range c.levels {
		out = append(out, byte(lv.bitCount>>24), byte(lv.bitCount>>16),
			byte(lv.bitCount>>8), byte(lv.bitCount))
		out = append(out, 1) // k=1 always
		out = append(out, lv.bits...)
	}
	return out
}

// Decode deserializes a cascade from bytes produced by Encode.
// Returns an error if the data is truncated, k != 1, or bit_count == 0.
func Decode(b []byte) (*Cascade, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("cascade: empty input")
	}
	numLevels := int(b[0])
	pos := 1
	levels := make([]level, 0, numLevels)
	for i := 0; i < numLevels; i++ {
		if pos+5 > len(b) {
			return nil, fmt.Errorf("cascade: truncated at level %d header", i)
		}
		bitCount := uint32(b[pos])<<24 | uint32(b[pos+1])<<16 |
			uint32(b[pos+2])<<8 | uint32(b[pos+3])
		k := b[pos+4]
		pos += 5
		if k != 1 {
			return nil, fmt.Errorf("cascade: level %d has k=%d, MUST be 1", i, k)
		}
		if bitCount == 0 {
			return nil, fmt.Errorf("cascade: level %d has bit_count=0", i)
		}
		byteCount := (bitCount + 7) / 8
		if pos+int(byteCount) > len(b) {
			return nil, fmt.Errorf("cascade: truncated at level %d bit array", i)
		}
		bits := make([]byte, byteCount)
		copy(bits, b[pos:pos+int(byteCount)])
		pos += int(byteCount)
		levels = append(levels, level{bitCount: bitCount, bits: bits})
	}
	if pos != len(b) {
		return nil, fmt.Errorf("cascade: %d trailing bytes after %d levels", len(b)-pos, numLevels)
	}
	return &Cascade{levels: levels}, nil
}

func sortedCopy(s []uint64) []uint64 {
	c := make([]uint64, len(s))
	copy(c, s)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c
}
