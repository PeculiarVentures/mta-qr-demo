// Package cbor provides deterministic CBOR encoding for MTA-QR log entries.
// All entries MUST use RFC 8949 §4.2 deterministic encoding:
// integer map keys, definite-length encoding, keys in bytewise lexicographic order.
// Non-canonical CBOR causes entry_hash mismatches that present as verification
// failures, not encoding errors — hard to diagnose.
package cbor

import (
	"fmt"

	cborlib "github.com/fxamacker/cbor/v2"
)

var encMode cborlib.EncMode
var decMode cborlib.DecMode

func init() {
	var err error
	// Deterministic encoding: sort map keys bytewise, definite-length everything.
	encOpts := cborlib.CanonicalEncOptions()
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cbor: failed to create deterministic enc mode: %v", err))
	}

	decOpts := cborlib.DecOptions{
		DupMapKey: cborlib.DupMapKeyEnforcedAPF,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cbor: failed to create dec mode: %v", err))
	}
}

// EntryTypeNull is the reserved null entry at index 0.
const EntryTypeNull byte = 0x00

// EntryTypeData is a bearer data assertion.
const EntryTypeData byte = 0x01

// EntryTypeKey is a key-bound assertion requiring possession proof.
const EntryTypeKey byte = 0x02

// DataAssertionLogEntry is the CBOR structure for a Type 0x01 entry.
// Field numbers match the spec: 2=[issuance,expiry], 3=schema_id, 4=claims.
// Field 1 is permanently reserved and MUST NOT be used.
type DataAssertionLogEntry struct {
	// Field 2: [issuance_time, expiry_time] Unix timestamps.
	Times [2]uint64 `cbor:"2,keyasint"`
	// Field 3: schema_id.
	SchemaID uint64 `cbor:"3,keyasint"`
	// Field 4: claims (schema-dependent, stored as raw CBOR).
	Claims interface{} `cbor:"4,keyasint"`
}

// KeyAssertionLogEntry is the CBOR structure for a Type 0x02 entry.
type KeyAssertionLogEntry struct {
	Times              [2]uint64 `cbor:"2,keyasint"`
	SchemaID           uint64    `cbor:"3,keyasint"`
	SubjectKeyHash     []byte    `cbor:"4,keyasint"`
	KeyAlgorithm       int64     `cbor:"5,keyasint"`
	AttestationFormat  uint64    `cbor:"6,keyasint,omitempty"`
	AttestationBinding []byte    `cbor:"7,keyasint,omitempty"`
	Claims             interface{} `cbor:"8,keyasint"`
}

// EncodeTBS encodes a log entry to its TBS (to-be-signed) bytes.
// Returns entry_type_byte || deterministic_CBOR(entry).
// The TBS is what gets hashed for the entry_hash and what appears in the
// QR payload tbs field and in log data tiles.
func EncodeTBS(entryType byte, entry interface{}) ([]byte, error) {
	if entryType == EntryTypeNull {
		// null_entry TBS is exactly one byte: 0x00. No CBOR follows.
		return []byte{EntryTypeNull}, nil
	}
	encoded, err := encMode.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("cbor: encode failed: %w", err)
	}
	tbs := make([]byte, 1+len(encoded))
	tbs[0] = entryType
	copy(tbs[1:], encoded)
	return tbs, nil
}

// EncodeDataAssertion encodes a DataAssertionLogEntry to TBS bytes.
func EncodeDataAssertion(issuanceTime, expiryTime, schemaID uint64, claims interface{}) ([]byte, error) {
	entry := DataAssertionLogEntry{
		Times:    [2]uint64{issuanceTime, expiryTime},
		SchemaID: schemaID,
		Claims:   claims,
	}
	return EncodeTBS(EntryTypeData, entry)
}

// EncodeKeyAssertion encodes a KeyAssertionLogEntry to TBS bytes.
func EncodeKeyAssertion(issuanceTime, expiryTime, schemaID uint64, subjectKeyHash []byte, keyAlg int64, attestFmt uint64, attestBinding []byte, claims interface{}) ([]byte, error) {
	entry := KeyAssertionLogEntry{
		Times:              [2]uint64{issuanceTime, expiryTime},
		SchemaID:           schemaID,
		SubjectKeyHash:     subjectKeyHash,
		KeyAlgorithm:       keyAlg,
		AttestationFormat:  attestFmt,
		AttestationBinding: attestBinding,
		Claims:             claims,
	}
	return EncodeTBS(EntryTypeKey, entry)
}

// Encode encodes any value using deterministic CBOR.
func Encode(v interface{}) ([]byte, error) {
	return encMode.Marshal(v)
}

// Decode decodes CBOR bytes into v.
func Decode(data []byte, v interface{}) error {
	return decMode.Unmarshal(data, v)
}

// RoundTripCanonical checks that data is already in canonical CBOR form by
// decoding and re-encoding it. Returns an error if the re-encoded form differs.
// Issuers SHOULD call this in their issuance pipeline.
func RoundTripCanonical(data []byte) error {
	var v interface{}
	if err := decMode.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("cbor: round-trip decode failed: %w", err)
	}
	reencoded, err := encMode.Marshal(v)
	if err != nil {
		return fmt.Errorf("cbor: round-trip encode failed: %w", err)
	}
	if string(reencoded) != string(data) {
		return fmt.Errorf("cbor: input is not canonical: got %x, re-encoded to %x", data, reencoded)
	}
	return nil
}
