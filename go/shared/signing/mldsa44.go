// Package signing — ML-DSA-44 (FIPS 204) implementation using cloudflare/circl.
// Signature size: 2420 bytes. Public key size: 1312 bytes. Seed size: 32 bytes.
// Signing is deterministic (hedged internally by circl but reproducible from seed+msg).
//
// TODO: Replace cloudflare/circl with crypto/mldsa when Go 1.27 ships.
// Tracking: https://github.com/golang/go/issues/77626
// The internal implementation (crypto/internal/fips140/mldsa) already exists in
// Go 1.26 but is inaccessible from external packages until the public API is exposed.
// Key sizes and wire format are identical, so the swap is ~15 lines in this file only —
// no changes to test vectors, interop matrix, or any other package.
package signing

import (
	"crypto/rand"
	"fmt"

	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type mlDSA44Signer struct {
	pub  *mldsa44.PublicKey
	priv *mldsa44.PrivateKey
}

// NewMLDSA44 generates a new ML-DSA-44 key pair.
func NewMLDSA44() (Signer, error) {
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mldsa44: generate key: %w", err)
	}
	return &mlDSA44Signer{pub: pub, priv: priv}, nil
}

// MLDSA44FromSeed derives a deterministic ML-DSA-44 key pair from a 32-byte seed.
// The seed MUST be exactly 32 bytes.
func MLDSA44FromSeed(seed []byte) (Signer, error) {
	if len(seed) != mldsa44.SeedSize {
		return nil, fmt.Errorf("mldsa44: seed must be %d bytes, got %d", mldsa44.SeedSize, len(seed))
	}
	var s [mldsa44.SeedSize]byte
	copy(s[:], seed)
	pub, priv := mldsa44.NewKeyFromSeed(&s)
	return &mlDSA44Signer{pub: pub, priv: priv}, nil
}

func (s *mlDSA44Signer) Sign(message []byte) ([]byte, error) {
	var sig [mldsa44.SignatureSize]byte
	// context = nil, randomized = false (deterministic)
	mldsa44.SignTo(s.priv, message, nil, false, sig[:])
	return sig[:], nil
}

func (s *mlDSA44Signer) PublicKeyBytes() []byte {
	b, _ := s.pub.MarshalBinary()
	return b
}

func (s *mlDSA44Signer) SigAlg() uint8 { return SigAlgMLDSA44 }

func verifyMLDSA44(message, sig, pubKey []byte) bool {
	if len(sig) != mldsa44.SignatureSize || len(pubKey) != mldsa44.PublicKeySize {
		return false
	}
	var pub mldsa44.PublicKey
	if err := pub.UnmarshalBinary(pubKey); err != nil {
		return false
	}
	return mldsa44.Verify(&pub, message, nil, sig)
}
