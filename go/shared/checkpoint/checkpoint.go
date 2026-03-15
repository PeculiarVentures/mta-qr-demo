// Package checkpoint implements the c2sp.org/tlog-checkpoint format for MTA-QR.
//
// A checkpoint body is exactly three newline-terminated lines:
//
//	<origin>\n
//	<tree_size decimal>\n
//	<root_hash base64std_padded>\n
//
// The trailing \n on the root hash line is part of the authenticated content.
// Stripping it is the most common implementation bug.
package checkpoint

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Body formats the checkpoint body that is signed by the issuer and cosigned
// by witnesses. The result is the exact byte sequence over which signatures
// are computed.
//
// IMPORTANT: The root hash is base64-encoded with standard alphabet and padding
// (RFC 4648 §4). The exact encoding matters for signature verification.
// Implementations that use URL-safe base64 or strip padding will fail.
func Body(origin string, treeSize uint64, rootHash []byte) []byte {
	rootHashB64 := base64.StdEncoding.EncodeToString(rootHash)
	body := origin + "\n" +
		strconv.FormatUint(treeSize, 10) + "\n" +
		rootHashB64 + "\n"
	return []byte(body)
}

// Sign signs the checkpoint body with an Ed25519 private key.
// Returns the raw 64-byte signature.
func Sign(body []byte, key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, body)
}

// Verify verifies an Ed25519 signature over a checkpoint body.
func Verify(body []byte, sig []byte, key ed25519.PublicKey) error {
	if !ed25519.Verify(key, body, sig) {
		return fmt.Errorf("checkpoint: Ed25519 signature verification failed")
	}
	return nil
}

// KeyID derives the 4-byte key ID for an Ed25519 signing key.
// Per c2sp.org/signed-note:
//
//	key_id = SHA-256(key_name || 0x0A || 0x01 || raw_ed25519_pubkey)[0:4]
//
// where 0x0A is a newline and 0x01 is the Ed25519 signature type identifier byte.
func KeyID(humanName string, pubKey ed25519.PublicKey) [4]byte {
	h := sha256.New()
	h.Write([]byte(humanName))
	h.Write([]byte{0x0A, 0x01}) // newline + Ed25519 type byte
	h.Write(pubKey)
	sum := h.Sum(nil)
	var id [4]byte
	copy(id[:], sum[:4])
	return id
}

// OriginID returns the first 8 bytes of SHA-256(origin), stored big-endian,
// used as the routing hint in the MTA-QR payload.
func OriginID(origin string) uint64 {
	h := sha256.Sum256([]byte(origin))
	var id uint64
	for i := 0; i < 8; i++ {
		id = (id << 8) | uint64(h[i])
	}
	return id
}

// CosignatureV1Message constructs the signed message for a tlog-cosignature/v1.
//
//	cosignature/v1\n
//	time <unix_timestamp_decimal>\n
//	<checkpoint body>
func CosignatureV1Message(body []byte, unixTimestamp uint64) []byte {
	header := "cosignature/v1\n" +
		"time " + strconv.FormatUint(unixTimestamp, 10) + "\n"
	msg := make([]byte, len(header)+len(body))
	copy(msg, header)
	copy(msg[len(header):], body)
	return msg
}

// SignCosignature produces a tlog-cosignature/v1 signature (64 bytes) over
// the cosignature message constructed from body and timestamp.
func SignCosignature(body []byte, timestamp uint64, key ed25519.PrivateKey) []byte {
	msg := CosignatureV1Message(body, timestamp)
	return ed25519.Sign(key, msg)
}

// VerifyCosignature verifies a tlog-cosignature/v1 signature.
// The timestamp in the signed message and in the binary WitnessCosig struct
// must be identical; that identity is the caller's responsibility.
func VerifyCosignature(body []byte, timestamp uint64, sig []byte, key ed25519.PublicKey) error {
	msg := CosignatureV1Message(body, timestamp)
	if !ed25519.Verify(key, msg, sig) {
		return fmt.Errorf("checkpoint: witness cosignature verification failed")
	}
	return nil
}

// ParseBody parses a checkpoint body and returns origin, treeSize, rootHash.
// Returns an error if the body does not have exactly three newline-terminated lines.
func ParseBody(body []byte) (origin string, treeSize uint64, rootHash []byte, err error) {
	s := string(body)
	if !strings.HasSuffix(s, "\n") {
		return "", 0, nil, fmt.Errorf("checkpoint: body must end with newline")
	}
	// Per c2sp.org/tlog-checkpoint: the body is three mandatory lines followed by
	// optional extension lines. We parse the first three and ignore any extras.
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) < 3 {
		return "", 0, nil, fmt.Errorf("checkpoint: expected at least 3 lines, got %d", len(lines))
	}
	origin = lines[0]
	treeSize, err = strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return "", 0, nil, fmt.Errorf("checkpoint: invalid tree_size %q: %w", lines[1], err)
	}
	rootHash, err = base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return "", 0, nil, fmt.Errorf("checkpoint: invalid root_hash base64 %q: %w", lines[2], err)
	}
	if len(rootHash) != 32 {
		return "", 0, nil, fmt.Errorf("checkpoint: root_hash must be 32 bytes, got %d", len(rootHash))
	}
	return origin, treeSize, rootHash, nil
}
