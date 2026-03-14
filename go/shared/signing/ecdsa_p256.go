package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ECDSAP256Signer signs with ECDSA P-256 / SHA-256.
// Wire format: raw r||s, 64 bytes (r and s each zero-padded to 32 bytes big-endian).
// This is the IEEE P1363 / WebCrypto raw format, NOT DER/ASN.1.
type ECDSAP256Signer struct {
	priv *ecdsa.PrivateKey
}

// NewECDSAP256 generates a fresh P-256 key pair.
func NewECDSAP256() (*ECDSAP256Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa-p256: generate key: %w", err)
	}
	return &ECDSAP256Signer{priv: priv}, nil
}

// ECDSAP256FromScalar constructs a signer from a 32-byte private scalar (big-endian).
func ECDSAP256FromScalar(scalar []byte) (*ECDSAP256Signer, error) {
	if len(scalar) != 32 {
		return nil, fmt.Errorf("ecdsa-p256: scalar must be 32 bytes, got %d", len(scalar))
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(scalar)
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(scalar)
	if priv.PublicKey.X == nil {
		return nil, fmt.Errorf("ecdsa-p256: invalid scalar")
	}
	return &ECDSAP256Signer{priv: priv}, nil
}

// Sign hashes message with SHA-256 and signs, returning 64-byte raw r||s.
func (s *ECDSAP256Signer) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa-p256: sign: %w", err)
	}
	return encodeRawSig(r, sv), nil
}

// PublicKeyBytes returns the uncompressed public key: 0x04 || X || Y (65 bytes).
func (s *ECDSAP256Signer) PublicKeyBytes() []byte {
	return encodeUncompressedPub(&s.priv.PublicKey)
}

func (s *ECDSAP256Signer) SigAlg() uint8 { return SigAlgECDSAP256 }

// verifyECDSAP256 verifies a raw r||s signature.
// pubKey must be 65-byte uncompressed (0x04 || X || Y).
func verifyECDSAP256(message, sig, pubKey []byte) bool {
	if len(sig) != 64 {
		return false
	}
	pub, err := decodeUncompressedPub(pubKey)
	if err != nil {
		return false
	}
	r, s := decodeRawSig(sig)
	digest := sha256.Sum256(message)
	return ecdsa.Verify(pub, digest[:], r, s)
}

// --- helpers ---

// encodeRawSig encodes r, s as zero-padded 32-byte big-endian, concatenated.
func encodeRawSig(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out
}

// decodeRawSig splits 64-byte raw sig into r, s big.Ints.
func decodeRawSig(raw []byte) (*big.Int, *big.Int) {
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	return r, s
}

// encodeUncompressedPub returns 0x04 || X || Y (65 bytes).
func encodeUncompressedPub(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(out[1+32-len(xBytes):33], xBytes)
	copy(out[33+32-len(yBytes):65], yBytes)
	return out
}

// decodeUncompressedPub parses a 65-byte uncompressed public key.
func decodeUncompressedPub(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, fmt.Errorf("ecdsa-p256: expected 65-byte uncompressed pub key (0x04 prefix), got %d bytes", len(b))
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
	pub.X = new(big.Int).SetBytes(b[1:33])
	pub.Y = new(big.Int).SetBytes(b[33:65])
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("ecdsa-p256: point not on curve")
	}
	return pub, nil
}
