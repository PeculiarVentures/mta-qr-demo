# mta-qr-demo

[![CI](https://github.com/PeculiarVentures/mta-qr-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/PeculiarVentures/mta-qr-demo/actions/workflows/ci.yml)

Reference implementation of **MTA-QR** — Merkle Tree Assertions for Verifiable QR Codes.

MTA-QR issues cryptographically authenticated QR codes backed by a transparency log. Each QR code carries a Merkle inclusion proof; a verifier checks it against a locally cached checkpoint signed by the issuer and witnessed by an independent quorum — entirely offline after a prefetch.

This repository provides four independent implementations (Go, TypeScript, Rust, Java) that pass a shared interop matrix across three signing algorithms and two payload modes.

**Documents in this repository:**
- [`SPEC.md`](SPEC.md) — Protocol specification v0.1
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Code structure and design decisions
- [`test-vectors/README.md`](test-vectors/README.md) — Test vector format
- [`browser-demo/README.md`](browser-demo/README.md) — In-browser demo usage

---

## Quick start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------| 
| Go | 1.22+ | Go SDK |
| Node.js | 20+ | TypeScript SDK |
| Rust | 1.85+ | Rust SDK |
| Java | 17+ | Java SDK |
| Maven | 3.8+ | Java build |
| Python | 3.10+ | Interop test runner |

### Run the test suites

```bash
cd go   && go test ./...
cd ts   && npm ci && npm run test:all
cd rust && cargo test
cd java && mvn test
```

### Run the interop matrix

```bash
python3 interop_test.py   # or: make interop
```

---

## Interop matrix

**96 cells — 4 issuers × 4 verifiers × 3 algorithms × 2 modes. All pass.**

Each verifier also asserts the `mode` field on the result matches the issued payload mode.

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

The issuer emits no proof hashes. In production a scanner fetches proof tiles from a tile server at scan time. The SDK verifier validates everything except inclusion (checkpoint, witnesses, TBS, expiry, `entry_index < tree_size`). See the Mode 2 limitation below.

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

## Payload modes

Set `mode` in `IssuerConfig` (default `1`):

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

**Mode 2 limitation.** This SDK's verifier does **not** verify Merkle inclusion for Mode 2 payloads. It validates the checkpoint, witness cosignatures, TBS structure, expiry, and `entry_index < tree_size`, but returns a successful result without cryptographic proof that the entry is in the log. Building a complete Mode 2 scanner requires a tile server and tile-fetching logic on top of this library. Use Mode 1 if you need guaranteed inclusion proof at verify time.

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

**Mode 2 does not verify inclusion.** Documented in the `Verifier` class docstring and `IssuerConfig.mode` field doc in all four SDKs. The `mode` field on `VerifyOk` lets callers detect and gate on it.

---

## Known limitations and open work

These are genuine gaps that should be addressed before production use. They are tracked here so they are not lost between sessions.

**Mode 2 tile server not implemented.** The SDK verifier accepts Mode 2 payloads without verifying Merkle inclusion. A complete Mode 2 deployment requires a tile server serving proof tiles at `GET /tile/{level}/{index}` and a scanner-side tile-fetching verifier that calls it. The protocol for tile format and addressing is not yet defined in `SPEC.md`.

**Revocation not implemented.** The verifier emits a `revocation check` step with a fixed "no revoked ranges (v0.1 open item)" message in all four implementations. The protocol for expressing and distributing revocation sets is not defined.

**Mode 0 (embedded checkpoint) not implemented.** The payload codec defines `mode=0` where the checkpoint and cosignatures are embedded directly in the payload for fully offline verification with no prefetch. The issuer and verifier in all four SDKs handle only modes 1 and 2.

**`key_assertion` (entry_type=0x02) not implemented.** The verifier rejects `entry_type != 0x01`. Key assertions with possession proofs (challenge-response) are defined in the spec but not implemented.

**Origin must be unique per (algorithm, key) pair.** Two issuers sharing an origin with different algorithms will cause the verifier's checkpoint cache to return the wrong root hash. This constraint is documented but not enforced at issuer construction time — the issuer should validate that the origin encodes the algorithm or refuse to start if the origin appears to conflict.

**SPEC.md does not describe Mode 2 tile addressing.** The spec covers the payload binary format and trust config schema but does not define the tile server API, tile addressing scheme, or tile verification algorithm needed to complete a Mode 2 deployment.

**Browser demo SDK bundle is not committed.** `browser-demo/deps/mta_qr_sdk.iife.js` is built by CI from `ts/src/browser-bundle.ts` via esbuild and not checked in. If the CI workflow is not yet wired to the GitHub Pages deployment step, the demo may serve a stale bundle.

---

## Key implementation facts

**CBOR.** Go uses `fxamacker/cbor/v2` with `CanonicalEncOptions()`. TypeScript uses `cborg`. Rust uses `ciborium` with an explicit pre-sort before encoding. Java uses `com.upokecenter.cbor` with sorted insertion. All four sort claim map keys alphabetically — required for canonical TBS bytes and cross-language Merkle proof validity.

**Ed25519 in TypeScript.** Node.js built-in `crypto`. No external Ed25519 dependency. Requires Node 20+.

**ECDSA P-256 wire format.** Raw r‖s (IEEE P1363), 64 bytes. Not DER.

**ML-DSA-44.** Go uses `cloudflare/circl v1.6.3`. TypeScript uses `@noble/post-quantum`. Rust uses `ml-dsa v0.1.0-rc.7`. Java uses BouncyCastle 1.79+ `pqc.crypto.mldsa`. 2420-byte signatures, 1312-byte public keys.

**Tiled two-level Merkle tree.** `BATCH_SIZE=16`. Inner proof: entry → batch root. Outer proof: batch root → parent root. The `inner_proof_count` byte in the payload encodes the split point. Mode 1 payloads embed both; Mode 2 payloads embed neither.

**Issuer signature dispatch.** Verifiers match the `issuer_key_name` field from the trust config against note signature lines — not by byte length. Length-based dispatch breaks with ML-DSA-44 (2420-byte signatures vs 64-byte for Ed25519/ECDSA-P256).

**Witnesses always use Ed25519** regardless of issuer `sig_alg`, per c2sp.org/tlog-cosignature.

**Self-describing payloads.** The server-side SDK issuers (Go, TypeScript, Rust, Java) always set the self-describing flag (bit 7 of the flags byte) and embed the origin string in the payload. The browser demo issues bound payloads (no origin embedded) as a deliberate simplification — the trust config is held in-page.

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
