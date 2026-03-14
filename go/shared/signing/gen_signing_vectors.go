//go:build ignore

// gen_signing_vectors.go generates the signing test vectors.
// Run: go run gen_signing_vectors.go
package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/mta-qr/demo/shared/signing"
)

// testMessage is a fixed checkpoint body used for all signing vectors.
// "example.com/mta-qr/v1\n3\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
const testMessageHex = "6578616d706c652e636f6d2f6d74612d71722f76310a330a414141414141414141414141414141414141414141414141414141414141414141414141414141414141413d0a"

func main() {
	msg, _ := hex.DecodeString(testMessageHex)

	vectors := []map[string]interface{}{}

	// --- Ed25519 ---
	// Fixed seed: 32 bytes of 0x42 (the answer)
	ed25519Seed := make([]byte, 32)
	for i := range ed25519Seed {
		ed25519Seed[i] = 0x42
	}
	edSigner, err := signing.Ed25519FromSeed(ed25519Seed)
	if err != nil {
		panic(err)
	}
	edSig, err := edSigner.Sign(msg)
	if err != nil {
		panic(err)
	}
	edPub := edSigner.PublicKeyBytes()

	// Verify round-trip
	if !signing.Verify(signing.SigAlgEd25519, msg, edSig, edPub) {
		panic("Ed25519 self-verify failed")
	}
	fmt.Fprintf(os.Stderr, "Ed25519: pub=%s sig=%s verify=true\n",
		hex.EncodeToString(edPub), hex.EncodeToString(edSig))

	vectors = append(vectors, map[string]interface{}{
		"id":          "signing-ed25519",
		"description": "Ed25519 sign+verify. Fixed 32-byte seed. Signature is deterministic.",
		"input": map[string]interface{}{
			"sig_alg":         6,
			"private_seed_hex": hex.EncodeToString(ed25519Seed),
			"message_hex":     testMessageHex,
		},
		"expected": map[string]interface{}{
			"public_key_hex":  hex.EncodeToString(edPub),
			"signature_hex":   hex.EncodeToString(edSig),
			"verify_result":   true,
		},
	})

	// --- ECDSA P-256 ---
	// Fixed scalar derived deterministically
	scalarSeed := sha256.Sum256([]byte("mta-qr-test-ecdsa-scalar"))
	// Ensure scalar is in [1, n-1]
	curve := elliptic.P256()
	n := curve.Params().N
	scalar := new(big.Int).SetBytes(scalarSeed[:])
	scalar.Mod(scalar, new(big.Int).Sub(n, big.NewInt(1)))
	scalar.Add(scalar, big.NewInt(1))
	scalarBytes := make([]byte, 32)
	sb := scalar.Bytes()
	copy(scalarBytes[32-len(sb):], sb)

	ecSigner, err := signing.ECDSAP256FromScalar(scalarBytes)
	if err != nil {
		panic(err)
	}

	ecPub := ecSigner.PublicKeyBytes()

	// ECDSA is randomized; sign once and record the signature.
	// The vector tests VERIFY a known-good signature, not sign.
	// Sign multiple times to get a valid sig, then hardcode the first.
	ecSig, err := ecSigner.Sign(msg)
	if err != nil {
		panic(err)
	}
	if !signing.Verify(signing.SigAlgECDSAP256, msg, ecSig, ecPub) {
		panic("ECDSA P-256 self-verify failed")
	}
	fmt.Fprintf(os.Stderr, "ECDSA-P256: pub=%s\n  sig=%s\n  verify=true\n",
		hex.EncodeToString(ecPub), hex.EncodeToString(ecSig))

	// Note: since ECDSA is randomized, the signature changes each run.
	// Both impls must:
	//   (a) verify the pre-recorded signature (tests cross-impl verify)
	//   (b) sign and verify their own output (tests round-trip)
	// Only (b) uses the fixed key; (a) is checked here but won't be in vectors
	// since we can't fix the sig without RFC 6979.
	// Instead, the vector provides: fixed key + fixed message + verify_instructions.
	// Each impl signs independently and verifies with the OTHER impl's verify.
	// The interop test drives this at runtime.

	vectors = append(vectors, map[string]interface{}{
		"id":          "signing-ecdsa-p256",
		"description": "ECDSA P-256 / SHA-256. Fixed private scalar derived from SHA-256('mta-qr-test-ecdsa-scalar'). Wire format: raw r||s (64 bytes, IEEE P1363). Public key: uncompressed 0x04||X||Y (65 bytes). Signature is RANDOMIZED — vector tests key derivation and verify-of-known-good-sig. The pre_recorded_sig was produced by the Go reference impl and must verify true in all impls.",
		"input": map[string]interface{}{
			"sig_alg":          4,
			"scalar_hex":       hex.EncodeToString(scalarBytes),
			"message_hex":      testMessageHex,
			"pre_recorded_sig": hex.EncodeToString(ecSig),
		},
		"expected": map[string]interface{}{
			"public_key_hex": hex.EncodeToString(ecPub),
			"verify_result":  true,
		},
	})

	out := map[string]interface{}{"signing_vectors": vectors}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}
