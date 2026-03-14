package signing_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mta-qr/demo/shared/signing"
)

// loadVectors loads the shared test-vectors/vectors.json.
func loadVectors(t *testing.T) map[string]map[string]interface{} {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	vectorPath := filepath.Join(filepath.Dir(thisFile), "../../../test-vectors/vectors.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var root struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	m := map[string]map[string]interface{}{}
	for _, raw := range root.Vectors {
		var v map[string]interface{}
		json.Unmarshal(raw, &v)
		m[v["id"].(string)] = v
	}
	return m
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("fromHex(%q): %v", s, err)
	}
	return b
}

// TestEd25519SigningVector verifies:
//   - public key derivation from fixed seed
//   - signature matches pre-recorded value (deterministic)
//   - verify(pre-recorded) == true
func TestEd25519SigningVector(t *testing.T) {
	vs := loadVectors(t)
	v := vs["signing-ed25519"]
	input := v["input"].(map[string]interface{})
	expected := v["expected"].(map[string]interface{})

	seed := fromHex(t, input["private_seed_hex"].(string))
	msg := fromHex(t, input["message_hex"].(string))
	wantPub := fromHex(t, expected["public_key_hex"].(string))
	wantSig := fromHex(t, expected["signature_hex"].(string))

	signer, err := signing.Ed25519FromSeed(seed)
	if err != nil {
		t.Fatalf("Ed25519FromSeed: %v", err)
	}

	// Public key derivation
	gotPub := signer.PublicKeyBytes()
	if hex.EncodeToString(gotPub) != hex.EncodeToString(wantPub) {
		t.Errorf("public key mismatch:\n  got  %x\n  want %x", gotPub, wantPub)
	}

	// Signature determinism (Ed25519 MUST be deterministic for fixed key+msg)
	gotSig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if hex.EncodeToString(gotSig) != hex.EncodeToString(wantSig) {
		t.Errorf("signature mismatch (Ed25519 must be deterministic):\n  got  %x\n  want %x", gotSig, wantSig)
	}

	// Verify pre-recorded signature
	if !signing.Verify(signing.SigAlgEd25519, msg, wantSig, wantPub) {
		t.Error("Verify(pre-recorded sig) returned false")
	}

	// Round-trip: verify own signature
	if !signing.Verify(signing.SigAlgEd25519, msg, gotSig, gotPub) {
		t.Error("Verify(own sig) returned false")
	}

	// Negative: flipped bit in sig must fail
	bad := make([]byte, len(gotSig))
	copy(bad, gotSig)
	bad[0] ^= 0x01
	if signing.Verify(signing.SigAlgEd25519, msg, bad, gotPub) {
		t.Error("Verify(corrupted sig) unexpectedly returned true")
	}

	// Negative: wrong message
	wrongMsg := append([]byte("WRONG"), msg...)
	if signing.Verify(signing.SigAlgEd25519, wrongMsg, gotSig, gotPub) {
		t.Error("Verify(wrong message) unexpectedly returned true")
	}
}

// TestECDSAP256SigningVector verifies:
//   - public key derivation from fixed scalar
//   - verify(pre_recorded_sig from Go reference impl) == true
//   - round-trip: sign and verify with own signature
//   - negative: corrupted sig, wrong message
func TestECDSAP256SigningVector(t *testing.T) {
	vs := loadVectors(t)
	v := vs["signing-ecdsa-p256"]
	input := v["input"].(map[string]interface{})
	expected := v["expected"].(map[string]interface{})

	scalar := fromHex(t, input["scalar_hex"].(string))
	msg := fromHex(t, input["message_hex"].(string))
	preRecordedSig := fromHex(t, input["pre_recorded_sig"].(string))
	wantPub := fromHex(t, expected["public_key_hex"].(string))

	signer, err := signing.ECDSAP256FromScalar(scalar)
	if err != nil {
		t.Fatalf("ECDSAP256FromScalar: %v", err)
	}

	// Public key derivation must be deterministic
	gotPub := signer.PublicKeyBytes()
	if hex.EncodeToString(gotPub) != hex.EncodeToString(wantPub) {
		t.Errorf("public key mismatch:\n  got  %x\n  want %x", gotPub, wantPub)
	}

	// Verify pre-recorded signature (cross-impl reference)
	if !signing.Verify(signing.SigAlgECDSAP256, msg, preRecordedSig, wantPub) {
		t.Error("Verify(pre-recorded sig) returned false — cross-impl verify broken")
	}

	// Round-trip: sign and verify own output
	gotSig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(gotSig) != 64 {
		t.Errorf("expected 64-byte raw sig, got %d bytes", len(gotSig))
	}
	if !signing.Verify(signing.SigAlgECDSAP256, msg, gotSig, gotPub) {
		t.Error("Verify(own sig) returned false")
	}

	// Negative: corrupted sig
	bad := make([]byte, len(gotSig))
	copy(bad, gotSig)
	bad[0] ^= 0x01
	if signing.Verify(signing.SigAlgECDSAP256, msg, bad, gotPub) {
		t.Error("Verify(corrupted sig) unexpectedly returned true")
	}

	// Negative: wrong algorithm dispatch — Ed25519 verify must not accept ECDSA sig
	if signing.Verify(signing.SigAlgEd25519, msg, gotSig, gotPub) {
		t.Error("Ed25519 Verify accepted ECDSA sig — algorithm dispatch broken")
	}
}

// TestCrossAlgorithmIsolation confirms that a valid sig for one algorithm
// does not verify under another, guarding against dispatch bugs.
func TestCrossAlgorithmIsolation(t *testing.T) {
	msg := []byte("cross-algorithm isolation test message")

	edSigner, err := signing.NewEd25519()
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := signing.NewECDSAP256()
	if err != nil {
		t.Fatal(err)
	}

	edSig, _ := edSigner.Sign(msg)
	ecSig, _ := ecSigner.Sign(msg)

	// Ed25519 sig must not verify under ECDSA P-256
	if signing.Verify(signing.SigAlgECDSAP256, msg, edSig, ecSigner.PublicKeyBytes()) {
		t.Error("ECDSA-P256 verify accepted Ed25519 sig")
	}
	// ECDSA sig must not verify under Ed25519
	if signing.Verify(signing.SigAlgEd25519, msg, ecSig, edSigner.PublicKeyBytes()) {
		t.Error("Ed25519 verify accepted ECDSA sig")
	}
	// Each must verify under its own algorithm
	if !signing.Verify(signing.SigAlgEd25519, msg, edSig, edSigner.PublicKeyBytes()) {
		t.Error("Ed25519 self-verify failed")
	}
	if !signing.Verify(signing.SigAlgECDSAP256, msg, ecSig, ecSigner.PublicKeyBytes()) {
		t.Error("ECDSA-P256 self-verify failed")
	}
}

// TestMLDSA44SigningVector verifies:
//   - public key derivation from fixed seed matches the canonical vector
//   - verify(pre_recorded_sig from Go reference impl) == true
//   - round-trip: sign and verify own signature
//   - negative: corrupted sig, wrong algorithm dispatch
func TestMLDSA44SigningVector(t *testing.T) {
	vs := loadVectors(t)
	v := vs["signing-mldsa44"]
	input := v["input"].(map[string]interface{})
	expected := v["expected"].(map[string]interface{})

	seed := fromHex(t, input["seed_hex"].(string))
	msg := fromHex(t, input["message_hex"].(string))
	preRecordedSig := fromHex(t, input["pre_recorded_sig"].(string))
	wantPub := fromHex(t, expected["public_key_hex"].(string))

	signer, err := signing.MLDSA44FromSeed(seed)
	if err != nil {
		t.Fatalf("MLDSA44FromSeed: %v", err)
	}

	// Public key derivation must match canonical vector
	gotPub := signer.PublicKeyBytes()
	if hex.EncodeToString(gotPub) != hex.EncodeToString(wantPub) {
		t.Errorf("public key mismatch:\n  got  %x\n  want %x", gotPub[:16], wantPub[:16])
	}

	// Verify pre-recorded signature (Go reference)
	if !signing.Verify(signing.SigAlgMLDSA44, msg, preRecordedSig, wantPub) {
		t.Error("Verify(pre-recorded sig) returned false")
	}

	// Round-trip: sign and verify own output (ML-DSA-44 is deterministic)
	gotSig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(gotSig) != 2420 {
		t.Errorf("expected 2420-byte sig, got %d bytes", len(gotSig))
	}
	if !signing.Verify(signing.SigAlgMLDSA44, msg, gotSig, gotPub) {
		t.Error("Verify(own sig) returned false")
	}

	// Negative: corrupted sig
	bad := make([]byte, len(gotSig))
	copy(bad, gotSig)
	bad[0] ^= 0x01
	if signing.Verify(signing.SigAlgMLDSA44, msg, bad, gotPub) {
		t.Error("Verify(corrupted sig) unexpectedly returned true")
	}

	// Negative: wrong algorithm dispatch
	if signing.Verify(signing.SigAlgEd25519, msg, gotSig, gotPub) {
		t.Error("Ed25519 verify accepted ML-DSA-44 sig — algorithm dispatch broken")
	}
}
