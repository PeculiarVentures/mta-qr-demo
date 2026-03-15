# Architecture

This document describes the code structure of `mta-qr-demo`, the design decisions behind it, and how to extend it.

---

## Overview

The repository contains two layers: HTTP services (Go and TypeScript) for running live issuers and verifiers, and standalone SDK libraries (Go, TypeScript, Rust, Java) that implement the full protocol without an HTTP layer.

### HTTP services

```
                        test-vectors/vectors.json
                        browser-demo/  ← browser demo (built from ts/sdk/)
                               │
              ┌────────────────┴────────────────┐
              │                                 │
         go/shared/                         ts/shared/
    merkle, cbor, checkpoint,          merkle, cbor, checkpoint,
    payload, signing                   payload, signing
              │                                 │
    ┌─────────┴──────────┐           ┌─────────┴──────────┐
    │                    │           │                    │
go/issuer (×3)      go/verifier  ts/issuer (×3)      ts/verifier
:8081 Ed25519        :8082        :3001 Ed25519        :3002
:8083 ECDSA P-256                 :3003 ECDSA P-256
:8085 ML-DSA-44                   :3005 ML-DSA-44
```

The two shared libraries are independently implemented and tested against the same canonical fixtures. The interop test confirms that any payload produced by any issuer verifies correctly with any verifier.

### SDK libraries

Four standalone libraries implementing the same protocol without HTTP:

| Directory | Language | Issuer | Verifier | Signers |
|-----------|----------|:------:|:--------:|---------|
| `ts/sdk/` | TypeScript | ✓ | ✓ | Local (Ed25519, ECDSA P-256, ML-DSA-44), GoodKey |
| `rust/`   | Rust       | ✓ | ✓ | Local (Ed25519, ECDSA P-256, ML-DSA-44), GoodKey |
| `java/`   | Java       | ✓ | ✓ | Local (Ed25519, ECDSA P-256, ML-DSA-44), GoodKey |
| `go/` (SDK portion) | Go | ✓ | ✓ | Local (Ed25519, ECDSA P-256, ML-DSA-44), GoodKey |

The SDKs share no code with the HTTP services. They use injectable signers and note providers, making them suitable for embedded use, testing, and environments without network access. All four pass a 96-cell cross-language interop matrix (4 issuers × 4 verifiers × 3 algorithms × 2 payload modes).

The TypeScript SDK (`ts/sdk/`) also provides a browser bundle entry point (`src/browser-bundle.ts`) compiled by esbuild into `browser-demo/deps/mta_qr_sdk.iife.js`, which the browser demo uses in place of inline protocol code.

---

## Protocol layer

The Go HTTP service uses `go/shared/`. The TypeScript HTTP service uses `ts/shared/`. The SDK libraries each contain equivalent implementations inline. All implementations are independently derived and verified against the same canonical test vectors.

### merkle

RFC 6962 §2.1 Merkle tree operations.

```
HashLeaf(data)  = SHA-256(0x00 || data)
HashNode(l, r)  = SHA-256(0x01 || l || r)
EntryHash(tbs)  = HashLeaf(tbs)            // same operation, named for clarity
```

The 0x00 / 0x01 domain separators prevent second-preimage attacks between leaf and internal nodes. `entry_index % 2 == 0` means the current node is a left child (sibling goes right); `% 2 == 1` means right child (sibling goes left). Getting this backwards produces wrong roots for odd-indexed entries and is a common implementation error.

The inclusion proof is an array of sibling hashes ordered leaf → root. `VerifyInclusion` recomputes the root and compares it to the cached value. No tree state is needed at verify time.

### cbor

Deterministic CBOR encoding (RFC 8949 §4.2) for log entries.

`DataAssertionLogEntry` is a CBOR map with integer keys 2, 3, 4. Field 1 is permanently reserved — see SPEC.md for why its absence is load-bearing.

**Non-canonical CBOR presents as a Merkle proof failure**, not a CBOR error. The verifier recomputes `entry_hash = SHA-256(0x00 ‖ tbs)` over the bytes in the payload; if the issuer encoded the same logical data differently, the hash differs and the proof path doesn't exist. A round-trip canonical check (`encode → decode → re-encode → compare bytes`) catches this at issuance.

Go library: `fxamacker/cbor/v2`, `CanonicalEncOptions()`.
TypeScript library: `cborg`. `cbor-x` does not produce canonical encoding for `Map` inputs with integer keys — use `cborg`. When decoding, pass `{ useMaps: true }` or integer-keyed `.get(2)` returns `undefined`.

### checkpoint

c2sp.org/tlog-checkpoint format. A checkpoint body is exactly:

```
<origin>\n
<tree_size decimal>\n
<root_hash base64std_padded>\n
```

Three lines, each terminated by `\n` including the final line. The trailing newline is part of the authenticated content; stripping it causes signature verification failure and is the most common checkpoint implementation bug.

The issuer signs this body directly. Witnesses sign a `cosignature/v1` message that prepends `"cosignature/v1\ntime <ts>\n"`. The timestamp is decimal Unix seconds, and must match the 8-byte big-endian value in the binary `WitnessCosig` struct.

**Witness cosignatures always use Ed25519** regardless of the issuer's algorithm. This is mandated by c2sp.org/tlog-cosignature.

Key ID derivation: `SHA-256("<name>+<base64(pubkey)>")[0:4]` — the first 4 bytes of the SHA-256 hash of the key name string without any hex_keyid component.

`OriginID` is `SHA-256(origin)[0:8]` stored as a big-endian uint64. It is a routing hint, not a collision-resistant identifier. Cache keys and revocation range keys MUST use the full origin string.

### payload

Binary encode/decode for `MTAQRPayload`. Big-endian integers throughout.

The flags byte packs: `mode[1:0] | sig_alg[4:2] | dual_sig[5] | self_describing[7]`.

Mode 1 (cached checkpoint) payload layout — two-byte tiled proof split:
```
version(1) flags(1) origin_id(8) tree_size(8) entry_index(8)
[origin_len(2) origin(N)]     ← self-describing mode only
proof_count(1) inner_proof_count(1) proof(proof_count×32)
tbs_len(2) tbs(N)
```

`proof_count` is the total number of 32-byte sibling hashes. `inner_proof_count` is the split point: the first `inner_proof_count` hashes are the inner (batch) proof (entry→batch root); the remaining hashes are the outer (parent tree) proof (batch root→parent root). The checkpoint root_hash is the parent tree root.

Mode 0 adds `root_hash(32) issuer_sig_len(2) issuer_sig(N) witness_count(1) cosigs(N×76)` at the end.

All length fields are bounds-checked before reading. Parsers reject payloads where any declared length would read past the buffer end. Parsers MUST verify `inner_proof_count ≤ proof_count`.

`entry_index == 0` is structurally invalid and MUST be rejected before any other verification.

### signing

Algorithm abstraction layer supporting Ed25519, ECDSA P-256, and ML-DSA-44 (FIPS 204).

```go
type Signer interface {
    Sign(message []byte) ([]byte, error)
    PublicKeyBytes() []byte
    SigAlg() uint8
}
```

```typescript
interface Signer {
    sign(message: Uint8Array): Uint8Array;
    publicKeyBytes(): Uint8Array;
    readonly sigAlg: number;
    readonly keyName: string; // note verifier key name (without hex_keyid)
}
```

`Verify(sigAlg, message, sig, pubKey)` dispatches by `sigAlg`. **Never dispatch by signature byte length** — Ed25519 and ECDSA P-256 are both 64 bytes. ML-DSA-44 is 2420 bytes. Any length-based heuristic breaks the moment a new algorithm is added.

`SigLen(sigAlg)` / `sigLen(sigAlg)` returns the expected raw byte length for pre-validation. `SigAlgName(sigAlg)` returns a human-readable name for UI and log output.

**Note format issuer signature dispatch** — the note parser identifies the issuer's signature line by matching `anchor.IssuerKeyName` (a string containing the base64-encoded public key) against the key name prefix in each note signature line. The `keyName` field on every `Signer` contains this identifier; issuers include it in `/trust-config` as `issuer_key_name`. Verifiers store it in their `TrustAnchor`. This is the only correct approach for multi-algorithm deployments.

**Ed25519** — Go: `crypto/ed25519` stdlib. TypeScript: Node.js `crypto` with PKCS#8/SPKI DER key objects (prefix `302e020100300506032b657004220420`). 64-byte signatures, 32-byte public keys.

**ECDSA P-256** — Go: `crypto/ecdsa`. TypeScript: `createSign("SHA256")`. Both produce DER natively; the code converts to raw r‖s (IEEE P1363, 64 bytes). Public keys: uncompressed `0x04 ‖ X ‖ Y`, 65 bytes.

**ML-DSA-44 (FIPS 204)** — Go: `github.com/cloudflare/circl/sign/mldsa/mldsa44`. TypeScript: `@noble/post-quantum/ml-dsa.js`. API difference: noble uses `sign(msg, secretKey)` / `verify(sig, msg, pubKey)` while circl uses `SignTo(priv, msg, ctx, randomized, sigBuf)` / `Verify(pub, msg, ctx, sig)`. 2420-byte signatures, 1312-byte public keys, 32-byte seed. Both implementations produce identical public keys from the same seed (validated by the `signing-mldsa44` canonical vector).

**Witnesses always use Ed25519** regardless of issuer `sig_alg`. Per c2sp.org/tlog-cosignature.

---

## Issuer (`go/issuer/`, `ts/issuer/`)

### Log (`go/issuer/log/log.go`)

In-memory append-only log. In production this would persist to a database and serve data tiles per c2sp.org/tlog-tiles.

At initialization:
1. Generates issuer key pair (via `signing.Signer`)
2. Generates two Ed25519 witness key pairs (always Ed25519)
3. Appends `null_entry` at index 0
4. Publishes initial checkpoint

On `AppendDataAssertion`:
1. Encodes CBOR entry (deterministic)
2. Appends to log with `entry_hash = SHA-256(0x00 ‖ tbs)`
3. Recomputes Merkle root over all entry hashes
4. Signs new checkpoint body with issuer key
5. Self-cosigns with both witness keys (demo: timestamps and cosignatures are computed inline; production would submit to the witness network)
6. Builds Mode 1 `MTAQRPayload` with inclusion proof

### HTTP server

`POST /issue` — decodes JSON claims, calls `log.AppendDataAssertion`, returns payload hex, base64, and a QR PNG URL.

`GET /checkpoint` — returns the current signed note in tlog-checkpoint format. The note is assembled from the in-memory checkpoint: body (formatted from origin, tree_size, root_hash), issuer signature line, and two witness cosignature lines. The `issuer_key_name` format is `<impl>-<alg>+<base64(pubkey)>`.

`GET /trust-config` — returns JSON that verifiers need to load this issuer: origin, origin_id hex, issuer public key hex, sig_alg, witness quorum, witness key details, checkpoint URL.

`GET /qr.png?payload=<base64url>` — renders the binary payload as a QR code PNG using `skip2/go-qrcode` or `qrcode` npm.

### Web UI

Single-page HTML embedded in the binary. Examples panel, form, and result display. "Verify with Go Verifier" and "Verify with TS Verifier" buttons open the verifier with the payload pre-filled via deep link (`?payload=<base64>`).

---

## Verifier (`go/verifier/`, `ts/verifier/`)

### Verification engine (`go/verifier/verify/verify.go`, `ts/verifier/main.ts`)

The engine holds:
- A map of trust anchors keyed by `origin_id` (for routing) and by full origin string
- A checkpoint cache keyed by `(full_origin, tree_size)` — full origin, not origin_id

`Verify(payloadBytes)` executes the 15-step flow and returns a `Result` with a `Steps []Step` array, each with `{name, ok, detail}`. The UI renders this as a trace.

The checkpoint cache avoids redundant fetches. On cache miss, `fetchAndVerify` fetches the note from the issuer endpoint, splits on `\n\n` to separate body from signature lines, verifies the issuer signature (algorithm from trust config, not from sig length), and verifies the witness cosignature quorum (Ed25519, always). The cache is then populated and the Merkle proof is checked against the cached root.

**Trust anchor loading** (`/load-trust-config`): fetches the issuer's `/trust-config` JSON, decodes the public key hex, parses the origin_id, and registers the anchor. At startup the verifiers also auto-attempt to load from known issuer URLs (configurable via `MTA_TRUST_CONFIG_URLS`).

### Note parser

The signed note format is:
```
<body lines>

— <keyname> <base64sig>
— <keyname> <base64sig>
```

The parser splits on `\n\n`, then for each signature line extracts the last space-delimited field as the base64 signature. The algorithm for the issuer signature comes from the trust config — never inferred from signature length.

Cosignature lines carry 72-byte base64: 8-byte big-endian timestamp + 64-byte Ed25519 signature. The parser identifies these by length (72 bytes raw vs 64 bytes raw for a plain Ed25519 signature).

### Web UI

Same single-page HTML pattern. Left panel: trust anchor loading + payload paste area. Right panel: result header (VALID / INVALID), metadata grid, claims display, step trace. Supports deep links (`?payload=<base64>`) from the issuer UI.

---

## Test harness

### TypeScript type checking

`tsc --noEmit` is included in `npm run test:all`. `skipLibCheck: true` is set in `tsconfig.json` to suppress type declaration errors in `cborg`'s own `.d.ts` files under strict `NodeNext` module resolution — a known upstream issue in cborg 4.x that does not affect runtime behavior. Our own code typechecks cleanly.

### Canonical test vectors (`test-vectors/vectors.json`)

7 vectors covering: checkpoint body format, null_entry hash, DataAssertionLogEntry CBOR, four-entry Merkle tree (leaf hashes, internal nodes, root, inclusion proof), entry hash construction, Ed25519 signing, ECDSA P-256 signing.

Both test suites load from this file and assert exact byte output. A vector failure isolates a specific layer disagreement — it's much easier to diagnose than an end-to-end interop failure.

See [`test-vectors/README.md`](test-vectors/README.md) for the format and how to add vectors.

### Interop test (`interop_test.py`)

Builds Go binaries, starts all services as subprocesses, runs the 12-cell positive matrix (3 algorithms × 4 impl pairs) plus 3 negative tests, prints per-step traces, exits 0 on 15/15.

Uses `MTA_PORT`, `MTA_ORIGIN`, and `MTA_SIG_ALG` environment variables to start multiple instances of the same binary with different configurations. Each algorithm variant gets a distinct origin string to avoid checkpoint cache collisions.

**Coverage note:** `interop_test.py` covers only the Go and TypeScript HTTP services. The Rust and Java SDK interop matrix (96 cells: 4 issuers × 4 verifiers × 3 algorithms × 2 modes) runs via `cargo test` and `mvn test` in their respective directories. Extending `interop_test.py` to cover Rust and Java requires wrapping those SDKs in HTTP servers.

### Browser demo (`browser-demo/`)

`browser-demo/index.html` is a self-contained browser implementation built from `browser-demo/index.template.html` by `browser-demo/build.py`. The build script injects three JavaScript bundles — nayuki QR encoder, noble post-quantum, and the MTA-QR SDK (`mta_qr_sdk.iife.js`) — into placeholder comments in the template.

The SDK bundle is compiled from `ts/sdk/src/browser-bundle.ts` by esbuild. CI rebuilds it from source on every push; the committed copy in `browser-demo/deps/` is a convenience snapshot. Both Mode 1 (proof embedded) and Mode 2 (proof deferred) work in-browser for Ed25519 and ML-DSA-44.

---

## Design decisions

**Why a tiled two-level Merkle tree?**  
See the dedicated section above. Short answer: bounds the inclusion proof to a hard maximum of 8 hashes (256 bytes) regardless of total log size, which keeps the QR code version fixed forever even under continuous rotation. A flat tree's proof grows by one hash every time the entry count doubles.

**Why in-memory log for the demo?**  
The protocol validation doesn't require persistence. A production implementation would back the log with a database and serve data tiles per c2sp.org/tlog-tiles. The log interface is isolated in `go/issuer/log/` so it can be swapped without touching the HTTP layer.

**Why self-cosign instead of hitting the real witness network?**  
Reduces external dependencies for a demo. The cosignature format is identical to what OmniWitness produces. To use the real witness network: post the signed checkpoint to a c2sp.org/tlog-witness compatible endpoint and use the returned cosignature line.

**Why not WebCrypto for ECDSA in TypeScript?**  
`crypto.subtle` is async-only, which would complicate the issuer's synchronous signing path. Node's `crypto.createSign` is synchronous and produces the same results. The abstraction is in `signing.ts`; swapping to WebCrypto for browser deployments is straightforward.

**Why `cborg` and not `cbor-x` for TypeScript CBOR?**  
`cbor-x` does not produce RFC 8949 §4.2 deterministic encoding for `Map` inputs with integer keys regardless of its `canonical` option. The interop exercise caught this: `cbor-x` produced `b90001` (2-byte map length) where canonical encoding requires `a1` (1-byte). `cborg` produces canonical output by default.

**Why is `entry_index == 0` rejected before trust anchor lookup?**  
The `null_entry` at index 0 carries no claims and is not a valid assertion. Rejecting it early means the trust anchor and cache are never consulted for an invalid payload, which simplifies the error surface and prevents any future confusion about what a zero-index payload means.

**Why a tiled two-level Merkle tree instead of a flat tree?**  
A flat N-entry tree produces proofs that grow as ⌈log₂(N)⌉ — one extra 32-byte hash every time the log doubles. With 10-second auto-rotation, that means a larger QR every ~10 seconds of operation. The tiled structure bounds growth:

- Inner tree (per-batch): BATCH_SIZE=16 entries → proof ≤ 4 hashes (128B, fixed forever)
- Outer tree (parent): bounded by OUTER_MAX_BATCHES=16 → proof ≤ 4 hashes (128B)
- Maximum total proof: 8 hashes = 256 bytes regardless of total log size

The checkpoint signs the **parent tree root** (Merkle root over batch roots), not a flat root over all entries. Verifiers walk two phases: entry→batch root (inner proof), then batch root→parent root (outer proof). The `innerProofCount` byte in the payload encodes the split point so verifiers don't need to know BATCH_SIZE out-of-band.

This also maps naturally to c2sp.org/tlog-tiles: each batch corresponds to a leaf tile at the standard tile height, and the parent tree corresponds to the tile hash tree.

**Why BATCH_SIZE=16 and OUTER_MAX_BATCHES=16?**  
Both constants are powers of 2, making tree levels exact (no unpaired-node edge cases at the maximum). 16 batches × 16 entries = 256 total entries before the outer tree rolls over. The outer roll resets the log to a new null_entry; existing payloads remain verifiable because they carry their own proof hashes. The browser demo, Go, and TypeScript all use these same constants.

**Why circl for ML-DSA-44 in Go and @noble/post-quantum in TypeScript?**  
These are the only available FIPS 204 implementations for their respective platforms at the time of writing. The key correctness test is that both produce identical public keys from the same 32-byte seed — confirmed by the `signing-mldsa44` canonical test vector. The noble library's verify API uses `verify(sig, msg, pubKey)` order while circl uses `Verify(pub, msg, ctx, sig)` — getting this wrong produces silent false negatives. The signing.ts wrapper normalises both to a consistent `verify(sigAlg, msg, sig, pubKey)` interface.

---

## Adding a new signing algorithm

1. **Register a `sig_alg` value** in the spec table (SPEC.md Cryptography section). Requires a C2SP note signature type registration for full interoperability.

2. **Implement in the Go HTTP service** (`go/shared/signing/`):
   - Add a `<alg>.go` file with a struct implementing `signing.Signer`
   - Add the `sig_alg` constant to `signing.go`
   - Add a `case` in `Verify()`, `SigLen()`, `PubKeyLen()`, and `SigAlgName()`

3. **Implement in the TypeScript HTTP service** (`ts/shared/signing.ts`):
   - Add a `SIG_ALG_*` constant
   - Add factory functions (`<alg>FromSeed(...)`, `new<Alg>()`) implementing `Signer`
   - Include a `keyName` field in the returned `Signer` — this is how verifiers identify the issuer's signature line in note format
   - Add a `case` in `verify()`, `sigLen()`, and `sigAlgName()`

4. **Implement in the TypeScript SDK** (`ts/sdk/src/signers/local.ts`, `ts/sdk/src/verify-sig.ts`):
   - Add a `local<Alg>()` factory function in `local.ts`
   - Add a `case` in the `verifySig()` dispatch in `verify-sig.ts`

5. **Implement in Rust** (`rust/src/signers/local.rs`, `rust/src/signing/verify.rs`):
   - Add a `LocalSigner::<alg>()` constructor in `local.rs`
   - Add a `case` in the `verify()` dispatch in `verify.rs`

6. **Implement in Java** (`java/src/main/java/.../signers/LocalSigner.java`, `.../signing/SignatureVerifier.java`):
   - Add a `LocalSigner.<alg>(byte[] seed)` factory method
   - Add a `case` in `SignatureVerifier.verify()`

7. **Add test vectors** (`test-vectors/vectors.json`):
   - A `signing-<alg>` vector with: fixed key material, a fixed message, the expected public key, and for deterministic algorithms the expected signature
   - For randomized algorithms (ECDSA-family): include a `pre_recorded_sig` produced by the reference implementation for cross-impl verify testing
   - All four test suites must load and pass this vector

8. **Add to the HTTP service issuers** (`go/issuer/main.go`, `ts/issuer/main.ts`):
   - Add a case in the `MTA_SIG_ALG` env-var switch

9. **Add to the interop matrix** (`interop_test.py`):
   - Add two service entries (one Go, one TS) with distinct origins encoding the algorithm
   - Add four positive cells (Go→Go, TS→TS, Go→TS, TS→Go)
   - Add to `docker-compose.yml` with `MTA_BASE_URL` set to the container's own service name and port



1. **Define the entry type byte** (0x03, 0x04, ...) and CBOR structure in SPEC.md.

2. **Add CBOR struct** in `go/shared/cbor/cbor.go` and encoding function.

3. **Add TypeScript equivalents** in `ts/shared/cbor.ts`.

4. **Add to the issuer's `/issue` handler** to accept and encode the new type.

5. **Add to the verifier's TBS decode step** — the switch on `entry_type_byte` at step 11 of the verification flow.

6. **Add a CBOR test vector** in `test-vectors/vectors.json` with a minimal example of the new entry type.
