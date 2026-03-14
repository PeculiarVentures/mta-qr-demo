# MTA-QR Browser Demo

A self-contained single-file browser implementation of the MTA-QR protocol.

## Usage

Open `index.html` directly in a browser — no server required, no build step.

```bash
open browser-demo/index.html
# or
python3 -m http.server 8000  # then visit http://localhost:8000/browser-demo/
```

## What it demonstrates

- **Mode 1 (Cached Checkpoint)** issuance and verification with full 15-step trace
- **Ed25519** and **ML-DSA-44 (FIPS 204)** issuer signing algorithms
- **Tiled Merkle tree** (BATCH_SIZE=16, OUTER_MAX_BATCHES=16) — see architecture comments in `index.html`
- **Auto-rotating credentials** (Ticket, Membership) with configurable interval
- **Tamper panel** to exercise all verification failure paths
- **Offline simulation** — cache hits work, cache misses fail

## Browser requirements

Chrome 113+, Firefox 130+, Safari 17+ (requires Ed25519 Web Crypto support)

## Dependencies (all vendored inline — no network required)

- **nayuki-qr-code-generator 1.8.0** (MIT) — QR code rendering to canvas
- **@noble/post-quantum 0.5.4** (MIT) — ML-DSA-44 signing for PQC mode
- **Web Crypto API** — Ed25519 signing, SHA-256

## Wire format

This demo uses the **tiled payload format** (two proof bytes instead of one):

```
version(1) | flags(1) | originId(8) | treeSize(8) | entryIndex(8)
proofCount(1) | innerProofCount(1) | proof[proofCount×32]
tbsLen(2) | tbs
```

The `innerProofCount` byte splits the proof array into inner (batch-level) and
outer (parent tree) segments. This is the same format used by the Go and
TypeScript implementations.

## Relationship to Go / TypeScript reference implementations

This demo implements the same tiled tree structure as the Go/TypeScript
implementations in `go/` and `ts/`. Payloads from any source should verify
in any verifier.
