# Test Vectors

Canonical fixtures shared by all four implementations (Go, TypeScript, Rust, Java). All test suites load from `vectors.json` and assert exact byte-level output before any integration or service tests run.

If a cross-implementation verification fails, run the vector tests first. A vector failure isolates the disagreement to a specific layer — CBOR encoding, checkpoint body format, Merkle path construction, signing — rather than requiring end-to-end debugging.

---

## Running

```bash
# Go
cd go && go test ./shared/... -v

# TypeScript (runs via SDK test suite)
cd ts/sdk && npm test

# Rust
cd rust && cargo test

# Java
cd java && mvn test
```

All four test suites load `vectors.json` and assert exact byte output. A vector failure isolates the disagreement to a specific layer (CBOR encoding, Merkle path, signing) rather than requiring end-to-end interop debugging.

---

## Vectors

### `checkpoint-body-v1`

Validates the exact byte sequence of a tlog-checkpoint body.

The most common implementation bug: stripping the trailing `\n` from any line. The body is exactly three lines, each terminated by `\n`, including the final line. Base64 `=` padding on the root hash is mandatory.

### `null-entry-hash`

Validates the entry hash for the `null_entry` at index 0.

TBS is a single byte `0x00`. Entry hash is `SHA-256(0x00 || 0x00)` — the RFC 6962 leaf hash applied to the one-byte TBS. A common mistake: computing `SHA-256(0x00)` (the SHA-256 of the domain separator alone) rather than `SHA-256(0x00 || 0x00)` (the SHA-256 of `0x00 || tbs`).

### `data-assertion-cbor`

Validates deterministic CBOR encoding of a `DataAssertionLogEntry`.

Map keys must be in ascending integer order: 2, 3, 4. Definite-length encoding. No floats. Both CBOR output and the resulting `entry_hash` must match exactly. If your CBOR library produces different output, you will see Merkle inclusion proof failures at the verifier — not CBOR errors — because the verifier recomputes `entry_hash` over the bytes in the payload and compares to the Merkle tree, not to a freshly encoded entry.

### `merkle-four-entry-tree`

Validates the RFC 6962 §2.1 Merkle construction over four entries.

Tests: leaf hash prefix (`0x00`), internal node prefix (`0x01`), left/right sibling placement by `entry_index` parity, inclusion proof construction, and proof verification round-trip.

Sibling placement: `entry_index % 2 == 0` means the current node is a left child — sibling is `SHA-256(0x01 || current || sibling)`. If `% 2 == 1`, current is right child — `SHA-256(0x01 || sibling || current)`. Getting this backwards produces wrong roots for odd-indexed entries.

### `entry-hash-construction`

Validates the full entry hash preimage: `0x00 || tbs` where `tbs` is `entry_type_byte || CBOR(AssertionLogEntry)`.

### `signing-ed25519`

Validates Ed25519 key derivation and signing from a fixed 32-byte seed.

Ed25519 signatures are deterministic. Both implementations must produce the exact same signature for the same seed and message. The seed is 32 bytes of `0x42`. The message is the checkpoint body from `checkpoint-body-v1`.

### `signing-mldsa44`

Validates ML-DSA-44 (FIPS 204) key derivation and cross-implementation signature verification.

The private seed is 32 bytes of `0x44`. Both Go (`cloudflare/circl`) and TypeScript (`@noble/post-quantum`) MUST derive the same 1312-byte public key from this seed — confirmed by the `public_key_hex` expected value. ML-DSA-44 signing is deterministic from seed; the `pre_recorded_sig` was produced by the Go reference and both implementations must verify it as true.

The interop test for ML-DSA-44: implementation A signs with its seed; implementation B verifies using the public key from this vector. This confirms that the 2420-byte signature wire format is identical between implementations.

Note: the noble library's verify API uses `verify(sig, msg, pubKey)` order. The circl library uses `Verify(pub, msg, ctx, sig)`. Both are normalised to `verify(sigAlg, msg, sig, pubKey)` in the shared signing abstraction.

---

## Vector format

```json
{
  "id": "unique-kebab-case-id",
  "description": "What is being tested and what the common failure mode is.",
  "input": { ... },
  "expected": { ... }
}
```

All hex strings: lowercase, no `0x` prefix, no spaces.

### `signing-ecdsa-p256`

Validates ECDSA P-256 public key derivation from a fixed private scalar, and cross-implementation signature verification.

The private scalar is `SHA-256("mta-qr-test-ecdsa-scalar") mod n`. Both implementations must derive the same public key (uncompressed, `0x04 ‖ X ‖ Y`, 65 bytes). ECDSA signing is randomized; the vector includes a `pre_recorded_sig` produced by the Go reference implementation which both implementations must verify as true.

---

## Adding a vector

1. Pick a unique `id` in `kebab-case`.

2. Write a clear `description` that states:
   - What specific behavior is being tested
   - What the common failure mode looks like from the outside (not just "wrong output" — what does the verifier see?)

3. Add the vector to `vectors.json`.

4. Add a test case to `go/shared/vectors_test.go`:
   ```go
   func TestYourVector(t *testing.T) {
       vs := loadVectors(t)
       v := vs["your-vector-id"]
       // ... parse input, call implementation, compare to expected
   }
   ```

5. Add a test case to `ts/sdk/src/test/vectors.test.ts`:
   ```typescript
   test("your-vector-id", () => {
       const v = vs.get("your-vector-id")!;
       // ... parse input, call implementation, compare to expected
   });
   ```

6. Add a test case to `rust/src/lib.rs` `vector_tests` module and `java/src/test/.../VectorTest.java` following the same pattern.

7. Run all four suites and confirm they pass before committing.

**Do not add a vector that one implementation fails** unless the failure exposes a real spec ambiguity that needs to be resolved. Vectors are canonical truth; failing tests mean the implementation or the spec needs to be fixed, not the vector.

