// Package signing provides the Signer interface and per-algorithm implementations
// for MTA-QR checkpoint body signing.
//
// Wire format for all algorithms: fixed-width raw encoding, no ASN.1 DER.
//   Ed25519:    64 bytes (r, already raw)
//   ECDSA P-256: 64 bytes (r||s, big-endian, zero-padded to 32 bytes each)
//
// Using raw format means the note parser cannot distinguish algorithms by
// signature length alone. The verifier must dispatch by sig_alg from the
// trust config — which is the correct design anyway.
package signing

import (
	"fmt"
)

// Signer signs and verifies messages for a specific algorithm.
type Signer interface {
	// Sign returns a raw signature over message.
	Sign(message []byte) ([]byte, error)
	// PublicKeyBytes returns the raw public key bytes.
	PublicKeyBytes() []byte
	// SigAlg returns the MTA-QR sig_alg byte.
	SigAlg() uint8
}

// Verify verifies a raw signature over message using the given algorithm and public key.
// Dispatches by sigAlg — callers must not rely on signature length to determine algorithm.
func Verify(sigAlg uint8, message, sig, pubKey []byte) bool {
	switch sigAlg {
	case SigAlgEd25519:
		return verifyEd25519(message, sig, pubKey)
	case SigAlgECDSAP256:
		return verifyECDSAP256(message, sig, pubKey)
	case SigAlgMLDSA44:
		return verifyMLDSA44(message, sig, pubKey)
	default:
		return false
	}
}

// SigLen returns the expected raw signature length for a given algorithm.
// Returns 0 for unknown algorithms.
// NOTE: Ed25519 and ECDSA-P256 both return 64 — never use length alone to
// identify algorithm. Use sigAlg from the trust config.
func SigLen(sigAlg uint8) int {
	switch sigAlg {
	case SigAlgEd25519:
		return 64
	case SigAlgECDSAP256:
		return 64 // r||s, 32 bytes each
	case SigAlgMLDSA44:
		return 2420
	default:
		return 0
	}
}

// PubKeyLen returns the expected raw public key length for a given algorithm.
func PubKeyLen(sigAlg uint8) int {
	switch sigAlg {
	case SigAlgEd25519:
		return 32
	case SigAlgECDSAP256:
		return 65 // uncompressed: 0x04 || X || Y
	case SigAlgMLDSA44:
		return 1312
	default:
		return 0
	}
}

// SigAlgName returns a human-readable algorithm name.
func SigAlgName(sigAlg uint8) string {
	switch sigAlg {
	case SigAlgEd25519:
		return "Ed25519"
	case SigAlgECDSAP256:
		return "ECDSA-P256"
	case SigAlgMLDSA44:
		return "ML-DSA-44"
	default:
		return fmt.Sprintf("unknown(0x%02x)", sigAlg)
	}
}

// sig_alg constants (subset of the full MTA-QR table).
const (
	SigAlgFNDSA512   uint8 = 0 // FN-DSA-512 (FALCON)
	SigAlgMLDSA44    uint8 = 1 // ML-DSA-44 (CRYSTALS-Dilithium)
	SigAlgMLDSA65    uint8 = 2 // ML-DSA-65
	SigAlgSLHDSA128s uint8 = 3 // SLH-DSA-128s
	SigAlgECDSAP256  uint8 = 4 // ECDSA P-256 / SHA-256
	SigAlgECDSAP384  uint8 = 5 // ECDSA P-384 / SHA-384
	SigAlgEd25519    uint8 = 6 // Ed25519
)
