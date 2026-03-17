# mta-qr-demo

[![CI](https://github.com/PeculiarVentures/mta-qr-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/PeculiarVentures/mta-qr-demo/actions/workflows/ci.yml)

Reference implementation of **MTA-QR** — Merkle Tree Assertions for Verifiable QR Codes.

MTA-QR issues cryptographically authenticated QR codes backed by a transparency log. Each QR code is a log entry with a Merkle inclusion proof tying it to a signed, witnessed checkpoint. Verification is offline after a one-time prefetch (Mode 1), or fully embedded in the payload for deployments where no checkpoint fetch is possible (Mode 0), or deferred to a tile server for high-throughput fixed-infrastructure scanning (Mode 2). All three modes are implemented. The protocol is algorithm-agnostic and PQC-ready.

This repository provides four independent implementations (Go, TypeScript, Rust, Java) that pass a shared interop matrix across three signing algorithms and two payload modes.

**Documents in this repository:**
- [`SPEC.md`](SPEC.md) — Protocol specification v0.1
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Code structure and design decisions
- [`COMPARISON.md`](COMPARISON.md) — Comparison with HMAC, per-assertion signatures, and rotating barcodes
- [`IMPLEMENTERS_GUIDE.md`](IMPLEMENTERS_GUIDE.md) — Practical implementation guide
- [`test-vectors/README.md`](test-vectors/README.md) — Test vector format
- [`browser-demo/README.md`](browser-demo/README.md) — In-browser demo usage

---

## Setup and quick start

### Prerequisites

| Tool | Version | Used for |
|------|---------|----------|
| Go | 1.22+ | Go HTTP services + Go SDK |
| Node.js | 20+ | TypeScript HTTP services + TypeScript SDK |
| Rust | 1.85+ | Rust SDK |
| Java | 17+ | Java SDK |
| Maven | 3.8+ | Java build |
| Python | 3.10+ | Interop test runner (`interop_test.py`) |

### Install dependencies

```bash
# TypeScript HTTP service
cd ts && npm ci

# TypeScript SDK
cd ts/sdk && npm install
```

Go, Rust, and Java fetch dependencies automatically on first build.

### Run the SDK test suites

```bash
cd go      && go test ./...
cd ts/sdk  && npm test
cd rust    && cargo test
cd java    && mvn test
```

### Run the TypeScript HTTP service tests

```bash
cd ts && npm run test:all
```

### Start the HTTP services locally

```bash
# Terminal 1 — Go issuer (Ed25519, port 8081)
cd go && go run ./issuer/

# Terminal 2 — Go verifier (port 8082)
cd go && go run ./verifier/

# Terminal 3 — TypeScript issuer (Ed25519, port 3001)
cd ts && npx tsx issuer/main.ts

# Terminal 4 — TypeScript verifier (port 3002)
cd ts && npx tsx verifier/main.ts
```

Each service reads `MTA_SIG_ALG` (`ed25519` / `ecdsa-p256` / `mldsa44`) and `MTA_ORIGIN` from the environment. Run multiple instances with different values to cover all three algorithms.

### Run the interop matrix (Go + TypeScript services)

```bash
python3 interop_test.py   # or: make interop
```

Builds Go binaries, starts all six issuers and two verifiers as subprocesses, runs 12 positive cells and 3 negative tests, exits 0 on 15/15.

### Docker Compose

```bash
docker compose up --build
```

---

## Interop matrix

**96 cells — 4 issuers × 4 verifiers × 3 algorithms × 2 modes. All pass.**

Each verifier asserts the `mode` field on the result matches the issued payload mode.

### Payload modes

MTA-QR has three payload modes defined in the protocol, all implemented across all four SDKs.

**Mode 0 — embedded (no checkpoint fetch).** The payload includes the inclusion proof and a compact cosigned checkpoint (root hash + issuer signature + witness cosignatures). No network access at scan time — the checkpoint is verified from the embedded signatures rather than fetched. A trust configuration (issuer and witness public keys) must still be pre-loaded; Mode 0 eliminates the checkpoint fetch, not the trust distribution step. Largest payload size (~440 bytes for Ed25519). Implemented in all four SDKs.

**Mode 1 — cached checkpoint (offline after prefetch).** The payload includes the inclusion proof but not the checkpoint. The verifier resolves the checkpoint from its local cache; on cache miss it fetches once and caches the result. This is the default mode and the right choice for most deployments.

**Mode 2 — online reference.** The payload contains the TBS (all metadata and claims) plus log coordinates, but no proof hashes. A scanner fetches the inclusion proof from a tile server at scan time and verifies it against the signed checkpoint. Smallest payload while retaining full metadata. The security properties of a correctly verified Mode 2 payload are identical to Mode 1 — the inclusion proof is cryptographically verifiable regardless of how it was delivered.

The practical difference is operational: Mode 2 requires network access at scan time, and there is a useful privacy property — because the verifier already holds the TBS from the physical scan, the tile server only needs to serve opaque 32-byte hashes (the "connective tissue" for the proof path). The tile server never sees PII; it cannot reconstruct claims from hashes alone.

**The SDK verifier does not implement tile fetching** — it validates the checkpoint, witnesses, and TBS but does not complete the inclusion proof step. Use Mode 1 when offline verification or no tile server is available. See the Mode 2 limitation in Known Limitations.

### Mode 1 — inclusion proof embedded (48 cells)

The issuer computes and embeds a two-phase tiled Merkle proof at issuance time. The verifier works fully offline after a one-time checkpoint prefetch.

| Issuer | Algorithm | Go | TS | Rust | Java |
|--------|-----------|:--:|:--:|:----:|:----:|
| Go | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Go | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Go | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| TS | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| TS | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| TS | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| Rust | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Rust | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Rust | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| Java | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Java | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Java | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |

### Mode 2 — proof deferred (48 cells)

The issuer embeds the TBS (full metadata) plus log coordinates, but emits no proof hashes. In production a scanner fetches the inclusion proof from a tile server at scan time and verifies it against the signed checkpoint — Mode 2 has identical security properties to Mode 1 when fully implemented. Privacy property: the tile server serves only hashes, never sees PII. The reference SDK validates checkpoint, witnesses, TBS, and expiry but does not implement tile fetching. See the Mode 2 limitation below.

| Issuer | Algorithm | Go | TS | Rust | Java |
|--------|-----------|:--:|:--:|:----:|:----:|
| Go | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Go | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Go | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| TS | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| TS | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| TS | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| Rust | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Rust | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Rust | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |
| Java | Ed25519 | ✓ | ✓ | ✓ | ✓ |
| Java | ECDSA P-256 | ✓ | ✓ | ✓ | ✓ |
| Java | ML-DSA-44 | ✓ | ✓ | ✓ | ✓ |

### Negative tests (must reject)

| Test | Result |
|------|--------|
| Ed25519 payload presented to verifier holding only ECDSA anchor | ✓ rejected |
| Tampered payload (bit flip in TBS — Merkle proof fails) | ✓ rejected |
| Payload for origin with no trust config loaded | ✓ rejected |
| Payload with trailing bytes after TBS | ✓ rejected |
| Trust config with `witness_quorum=0` | ✓ rejected at parse time |
| Trust config with `witness_quorum > len(witnesses)` | ✓ rejected at parse time |

---

## Payload mode API

Set `mode` in `IssuerConfig` (default `1`; see the Interop matrix section above for a description of each mode):

```go
// Go
issuer.New(issuer.Config{Origin: "...", Mode: 2}, signer)
```
```typescript
// TypeScript
new Issuer({ origin: "...", schemaId: 1, mode: 2 }, signer)
```
```rust
// Rust
IssuerConfig { origin: "...".into(), mode: Some(2), ..Default::default() }
```
```java
// Java
Issuer.builder().origin("...").mode(2).signer(signer).build()
```

The `VerifyOk`/`VerifyResult` returned by `verify()` includes a `mode` field so callers can distinguish the two cases.

**Mode 2 tile fetching not implemented.** This SDK's verifier does **not** fetch or verify the inclusion proof for Mode 2 payloads. It validates the checkpoint, witness cosignatures, TBS structure, expiry, and `entry_index < tree_size`, then returns a result marked `mode=2`. The inclusion proof is cryptographically verifiable — when a complete Mode 2 scanner fetches the proof and checks it against the witnessed root, the security properties are identical to Mode 1. Building that scanner requires a tile-fetching implementation and a defined tile server API, neither of which exists yet. Use Mode 1 when you need inclusion proof verification today.

---

## Comparison with other approaches

Four QR authentication approaches have seen real deployment at scale: HMAC (shared-secret MAC), per-assertion signatures (EU Digital COVID Certificate model), rotating barcodes (Ticketmaster SafeTix model), and MTA-QR. The approaches differ on PQC migration path, offline capability, credential lifetime, revocation, and whether verifier independence is architecturally supported.

The full analysis is in [`COMPARISON.md`](COMPARISON.md), including a property matrix and guidance on which approach fits which deployment context.

---

## Security properties

All four implementations enforce the following and they are covered by the test suite.

**Witness quorum is mandatory.** The trust config parser rejects `witness_quorum < 1` and `witness_quorum > len(witnesses)` at load time. A zero quorum would trivially pass all cosignature checks — this is caught at parse, not at verify time.

**Trailing bytes are rejected.** All four implementations check `pos == len(data)` after decoding the payload. A payload with appended garbage cannot pass as valid.

**Merkle root comparison is constant-time.** `crypto.timingSafeEqual` (TypeScript), `subtle.ConstantTimeCompare` (Go), `subtle::ConstantTimeEq` (Rust), `MessageDigest.isEqual` (Java). All previously used short-circuiting equality.

**Checkpoint cache is bounded.** Capped at 1000 entries with insertion-order eviction in all four implementations. Payloads with rapidly incrementing `tree_size` values cannot exhaust memory.

**CBOR encoding is canonical.** All four implementations sort map keys alphabetically before encoding the TBS. Non-canonical encoding produces a different entry hash and fails cross-language verification. This is enforced by the interop matrix — any issuer's payload verifies with any verifier only if the TBS bytes are bit-identical.

**ML-DSA-44 uses FIPS 204.** All four produce identical key pairs from the same 32-byte seed via `ML-DSA.KeyGen_internal(ξ)`. The Java implementation uses BouncyCastle 1.79+ `MLDSAKeyPairGenerator` — BC 1.78.x `DilithiumKeyPairGenerator` implements pre-standardisation Dilithium and produces different keys from the same seed, breaking cross-language verification.

**Test keys are opaque.** Test seeds are 32-byte values generated from `/dev/urandom`, not derived from strings. This prevents the `sha256("test-ed25519")` pattern from being copied into production.

**Revocation uses a Bloom filter cascade for constant-time, offline-capable checks.** The issuer builds a multi-level Bloom filter cascade (CRLite-inspired, not wire-compatible) over the sets of revoked and valid entry indices. The signed artifact is ~7 bytes for a small log and grows logarithmically. Verifiers fetch it on cache miss, verify the issuer signature with algorithm binding, and query it in constant time with no false negatives. The check is fail-closed — a missing or invalid artifact causes verification to fail. Bandwidth cost per check: approximately one artifact fetch per STALE_THRESHOLD entries (default 32), not one per verification.

**Mode 2 does not verify inclusion.** Documented in the `Verifier` class docstring and `IssuerConfig.mode` field doc in all four SDKs. The `mode` field on `VerifyOk` lets callers detect and gate on it.

---

## Known limitations and open work

These are genuine gaps that should be addressed before production use. They are tracked here so they are not lost between sessions.

**Mode 2 tile server not implemented.** The SDK verifier accepts Mode 2 payloads without verifying Merkle inclusion. A complete Mode 2 deployment requires a tile server serving proof tiles at `GET /tile/{level}/{index}` and a scanner-side tile-fetching verifier that calls it. The tile server API and addressing scheme are not yet defined in `SPEC.md`.

**Revocation delay.** When an entry is revoked, the revocation is effective only once a new checkpoint has been issued and the verifier's cached artifact becomes stale (STALE_THRESHOLD=32 entries). Between revocation and cache expiry, a revoked credential may still pass verification. This is an inherent trade-off in transparency log models — the window is bounded by checkpoint frequency and STALE_THRESHOLD, not unbounded. Deployments with strict revocation requirements should set short checkpoint intervals and tune STALE_THRESHOLD accordingly.

**Revocation is implemented** in all four language SDKs (Go, TypeScript, Rust, Java). Issuers serve a signed Bloom filter cascade at `GET /revoked` and accept `POST /revoke` for demo purposes. Verifiers fetch the artifact on cache miss, verify the issuer signature with algorithm binding, apply a staleness check (STALE_THRESHOLD=32 entries), and query the cascade fail-closed. The cascade algorithm is cross-verified against locked test vector bytes in all four languages. See SPEC.md §Revocation for the normative wire format and construction parameters.

**Remaining revocation gap:** Mode 0 deployments require a pre-loaded cached artifact since no network fetch occurs at scan time. The current verifiers skip the revocation check (fail-open) when no `revocation_url` is present in the trust config, which is the correct behavior for Mode 0 pre-loaded deployments. Verifier operators that require hard revocation guarantees at Mode 0 scan time must pre-load and periodically refresh the artifact out of band.

**Mode 0 (embedded checkpoint) implemented.** Issuers embed the root hash, issuer signature, and witness cosignatures directly in the payload. Verifiers reconstruct the checkpoint body from these fields and verify all signatures without any network access. Mode 0 payloads are ~440 bytes for Ed25519 with a 2-witness quorum. All four SDKs (Go, TypeScript, Rust, Java) issue and verify Mode 0 payloads; cross-implementation interop is verified in the interop matrix.

**`key_assertion` (entry_type=0x02) not implemented.** The verifier rejects `entry_type != 0x01`. Key assertions with possession proofs (challenge-response) are defined in the spec but not implemented.

**Origin must be unique per (algorithm, key) pair.** Two issuers sharing an origin with different algorithms will cause the verifier's checkpoint cache to return the wrong root hash. This constraint is documented but not enforced at issuer construction time — the issuer should validate that the origin encodes the algorithm or refuse to start if the origin appears to conflict.

**SPEC.md does not describe Mode 2 tile addressing.** The spec covers the payload binary format and trust config schema but does not define the tile server API, tile addressing scheme, or tile verification algorithm needed to complete a Mode 2 deployment.

**Browser demo SDK bundle is not committed as a source artifact.** `browser-demo/deps/mta_qr_sdk.iife.js` is committed as a convenience snapshot but CI rebuilds it from `ts/sdk/src/browser-bundle.ts` on every push. The committed copy may be slightly stale between pushes; the CI-built version is authoritative.

**`interop_test.py` covers only Go and TypeScript HTTP services.** The Rust and Java SDK interop matrix runs via `cargo test` and `mvn test`. Extending `interop_test.py` to include Rust and Java requires wrapping those SDKs in HTTP server binaries with the same `/issue`, `/verify`, and `/trust-config` endpoints as the existing Go and TypeScript services.

---

## Key implementation facts

**CBOR.** Go uses `fxamacker/cbor/v2` with `CanonicalEncOptions()`. TypeScript uses `cborg`. Rust uses `ciborium` with an explicit pre-sort before encoding. Java uses `com.upokecenter.cbor` with sorted insertion. All four sort claim map keys alphabetically — required for canonical TBS bytes and cross-language Merkle proof validity.

**Ed25519 in TypeScript.** Node.js built-in `crypto`. No external Ed25519 dependency. Requires Node 20+.

**ECDSA P-256 wire format.** Raw r‖s (IEEE P1363), 64 bytes. Not DER.

**ML-DSA-44.** Go uses `cloudflare/circl v1.6.3`. TypeScript uses `@noble/post-quantum`. Rust uses `ml-dsa v0.1.0-rc.7`. Java uses BouncyCastle 1.79+ `pqc.crypto.mldsa`. 2420-byte signatures, 1312-byte public keys.

**Tiled two-level Merkle tree.** `BATCH_SIZE=16`. Inner proof: entry → batch root. Outer proof: batch root → parent root. The `inner_proof_count` byte in the payload encodes the split point. Mode 1 payloads embed both; Mode 2 payloads embed neither.

**Issuer signature dispatch.** Verifiers match the `issuer_key_name` field from the trust config against note signature lines — not by byte length. Length-based dispatch breaks with ML-DSA-44 (2420-byte signatures vs 64-byte for Ed25519/ECDSA-P256).

**Witnesses always use Ed25519** regardless of issuer `sig_alg`, per c2sp.org/tlog-cosignature.

**Bound vs self-describing payloads.** The flags byte has a `self_describing` bit (bit 7). When set, the payload envelope contains the full origin string so a verifier can identify the issuer without consulting an external directory. When clear (bound mode), the payload contains only the 8-byte `origin_id` (a truncated SHA-256 of the origin string) and the verifier must already know which full origin that corresponds to.

The server-side SDK issuers (Go, TypeScript, Rust, Java) always use self-describing mode — the origin is embedded in every payload. The browser demo uses bound mode as a deliberate simplification: the trust config is held in-page and the origin doesn't need to be transmitted. Self-describing mode is the correct choice for real deployments where verifiers load trust configs independently.

**CBOR claim values.** Claim values may be strings or integers. The Java CBOR decoder handles both — earlier versions called `.AsString()` unconditionally, which failed on integer-valued claims.

---

## References

- [`SPEC.md`](SPEC.md) — protocol specification
- [draft-davidben-tls-merkle-tree-certs-09](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/)
- [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
- [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature)
- [transparency.dev](https://transparency.dev)
- [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) — Merkle hash tree
- [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) — CBOR deterministic encoding
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA standard
