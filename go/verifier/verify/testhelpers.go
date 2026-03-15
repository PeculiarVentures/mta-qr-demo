package verify

// This file exposes test helpers for the verify package.
// These functions are compiled into production binaries (Go has no test-only
// package members outside _test.go files in external packages), but they are
// small and carry no runtime cost in the hot path.

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// OriginIDFromString computes the 8-byte origin_id (big-endian uint64 of the
// first 8 bytes of SHA-256(origin)) for use in test anchor construction.
func OriginIDFromString(origin string) uint64 {
	h := sha256.Sum256([]byte(origin))
	return binary.BigEndian.Uint64(h[:8])
}

// InjectCache inserts a root hash into the verifier's checkpoint cache for
// (origin, treeSize) so tests can exercise the verification path without
// requiring a live checkpoint endpoint.
func (v *Verifier) InjectCache(origin string, treeSize uint64, rootHash []byte) {
	cacheKey := origin + ":" + uint64str(treeSize)
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cacheOrder) >= maxCacheEntries {
		delete(v.cache, v.cacheOrder[0])
		v.cacheOrder = v.cacheOrder[1:]
	}
	v.cacheOrder = append(v.cacheOrder, cacheKey)
	v.cache[cacheKey] = &CachedCheckpoint{
		TreeSize:  treeSize,
		RootHash:  rootHash,
		FetchedAt: time.Now(),
	}
}

// uint64str formats a uint64 as a decimal string without importing fmt.
func uint64str(n uint64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 20)
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
