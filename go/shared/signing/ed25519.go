package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Ed25519Signer signs with Ed25519.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewEd25519() generates a fresh Ed25519 key pair.
func NewEd25519() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: generate key: %w", err)
	}
	return &Ed25519Signer{priv: priv, pub: pub}, nil
}

// Ed25519FromSeed constructs an Ed25519Signer from a 32-byte seed.
func Ed25519FromSeed(seed []byte) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Ed25519Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

func (s *Ed25519Signer) PublicKeyBytes() []byte {
	return []byte(s.pub)
}

func (s *Ed25519Signer) SigAlg() uint8 { return SigAlgEd25519 }

func verifyEd25519(message, sig, pubKey []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != 64 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey), message, sig)
}
