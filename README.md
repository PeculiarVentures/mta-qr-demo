# mta-qr-demo

<!-- CI badge: replace REPO_PATH with your GitHub org/repo before pushing -->
![CI](https://github.com/mta-qr-demo/actions/workflows/ci.yml/badge.svg)

Reference implementation of **MTA-QR** — Merkle Tree Assertions for Verifiable QR Codes.

MTA-QR issues cryptographically authenticated QR codes backed by a transparency log. Each QR code carries a Merkle inclusion proof; a verifier checks it against a locally cached checkpoint signed by the issuer and witnessed by an independent quorum — entirely offline after a prefetch.

This repository proves the protocol is implementable by providing two independent implementations (Go and TypeScript) that pass a shared canonical test-vector suite and verify each other's payloads across two signing algorithms.

**Documents in this repository:**
- [`SPEC.md`](SPEC.md) — Protocol specification v0.1
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Code structure and design decisions
- [`test-vectors/README.md`](test-vectors/README.md) — Test vector format and how to add new ones
- [`SETUP.md`](SETUP.md) — Pre-push checklist (Go module path + CI badge)
- [`browser-demo/README.md`](browser-demo/README.md) — In-browser demo usage

---

## Quick start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.22+ | Go issuer and verifier |
| Node.js | 20+ | TypeScript issuer and verifier |
| Python | 3.10+ | Interop test runner |
| `tsx` | any | TypeScript runner — installed via `npm install` in `ts/` (dev dependency) |

### Install TypeScript dependencies

```bash
cd ts && npm install
```

Or with Make (also installs and runs all tests):

```bash
make install && make test
```

### Run the test suites

```bash
# Go: shared library vectors + signing self-tests
cd go && go test ./...

# TypeScript: vectors, signing self-tests, and type-check
cd ts && npm run test:all
```

`npm run test:all` runs vector tests, signing tests, and `tsc --noEmit`. All must pass before running services.

### Start services locally

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

Open the UIs:

| Service | URL | What it does |
|---------|-----|--------------|
| Go issuer | http://localhost:8081 | Issue QR codes with example claims |
| Go verifier | http://localhost:8082 | Paste a payload, see 15-step verification trace |
| TS issuer | http://localhost:3001 | Same as Go issuer, different stack |
| TS verifier | http://localhost:3002 | Same as Go verifier, different stack |

### Run the automated interop matrix

```bash
python3 interop_test.py
# or
make interop
```

Builds Go binaries, starts all eight services (6 issuers + 2 verifiers), runs the 12-cell positive matrix and 3 negative tests. Exits 0 on 15/15.

### Docker Compose

```bash
docker compose up --build
```

---

## Interop matrix

The matrix validates that any issuer payload verifies correctly with any verifier, across three signing algorithms. Positive tests confirm correct acceptance; negative tests confirm correct rejection.

**Positive (12 cells):**

| Issuer | Verifier | Algorithm | Result |
|--------|----------|-----------|--------|
| Go | Go | Ed25519 | ✓ |
| TS | TS | Ed25519 | ✓ |
| Go | TS | Ed25519 | ✓ |
| TS | Go | Ed25519 | ✓ |
| Go | Go | ECDSA P-256 | ✓ |
| TS | TS | ECDSA P-256 | ✓ |
| Go | TS | ECDSA P-256 | ✓ |
| TS | Go | ECDSA P-256 | ✓ |
| Go | Go | ML-DSA-44 (FIPS 204) | ✓ |
| TS | TS | ML-DSA-44 (FIPS 204) | ✓ |
| Go | TS | ML-DSA-44 (FIPS 204) | ✓ |
| TS | Go | ML-DSA-44 (FIPS 204) | ✓ |

**Negative (3 cells — must reject):**

| Test | Result |
|------|--------|
| Ed25519 payload presented to verifier holding only ECDSA anchor | ✓ rejected |
| Tampered payload (bit flip in TBS — Merkle proof fails) | ✓ rejected |
| Payload for origin with no trust config loaded | ✓ rejected |

---

## Environment variables

All services read configuration from environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `MTA_PORT` | 8081/8082/3001/3002 | Listening port |
| `MTA_ORIGIN` | `demo.mta-qr.example/…` | Log origin string. **Must be unique per (key, algorithm) pair.** |
| `MTA_SIG_ALG` | `""` (Ed25519) | Signing algorithm: `""` or `"ed25519"` for Ed25519; `"ecdsa-p256"` or `"4"` for ECDSA P-256; `"mldsa44"` or `"ml-dsa-44"` or `"1"` for ML-DSA-44 (FIPS 204). |
| `MTA_BASE_URL` | `""` | Base URL the issuer advertises in `/trust-config` for the `checkpoint_url` field. Required in Docker/remote deployments where `localhost` in the trust config would resolve to the verifier container. Example: `http://go-issuer-ed25519:8081` |
| `MTA_TRUST_CONFIG_URLS` | `""` | Comma-separated `/trust-config` URLs to auto-load at startup (Docker Compose). |

**Origin uniqueness is required.** Two issuers with different algorithms MUST have different origins. Sharing an origin between algorithm variants causes the verifier's checkpoint cache to return the wrong root, producing a Merkle proof failure with no obvious diagnostic.

### Running ECDSA P-256 and ML-DSA-44 issuers

```bash
# Go ECDSA P-256
MTA_SIG_ALG=ecdsa-p256 MTA_PORT=8083 \
  MTA_ORIGIN=demo.mta-qr.example/go-issuer/ecdsa-p256/v1 \
  go run ./go/issuer/

# Go ML-DSA-44 (FIPS 204)
MTA_SIG_ALG=mldsa44 MTA_PORT=8085 \
  MTA_ORIGIN=demo.mta-qr.example/go-issuer/mldsa44/v1 \
  go run ./go/issuer/

# TypeScript ECDSA P-256
MTA_SIG_ALG=ecdsa-p256 MTA_PORT=3003 \
  MTA_ORIGIN=demo.mta-qr.example/ts-issuer/ecdsa-p256/v1 \
  npx tsx ts/issuer/main.ts

# TypeScript ML-DSA-44
MTA_SIG_ALG=mldsa44 MTA_PORT=3005 \
  MTA_ORIGIN=demo.mta-qr.example/ts-issuer/mldsa44/v1 \
  npx tsx ts/issuer/main.ts
```

Verifiers auto-discover the algorithm from the issuer's `/trust-config` endpoint. No verifier configuration change is needed.

---

## HTTP API

### Issuer endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/issue` | Issue an assertion. Body: `{"schema_id": 1, "ttl_seconds": 3600, "claims": {...}}` |
| `GET` | `/checkpoint` | Current cosigned checkpoint (tlog-checkpoint signed-note format) |
| `GET` | `/trust-config` | Trust configuration JSON: origin, issuer public key, sig_alg, witness keys, checkpoint URL |
| `GET` | `/qr.png?payload=<base64url>` | Render payload as QR code PNG |

### Verifier endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web UI (accepts `?payload=<base64>` to pre-fill) |
| `POST` | `/verify` | Verify a payload. Body: `{"payload_hex": "..."}` or `{"payload_b64": "..."}` |
| `GET` | `/load-trust-config?url=<url>` | Load a trust anchor from an issuer |
| `GET` | `/anchors` | List loaded trust anchors |

### Verification result

```json
{
  "valid": true,
  "entry_index": 1,
  "tree_size": 2,
  "origin": "demo.mta-qr.example/go-issuer/ed25519/v1",
  "mode": 1,
  "sig_alg": 6,
  "schema_id": 1,
  "claims": {"subject": "demo"},
  "steps": [
    {"name": "Decode payload",    "ok": true,  "detail": "mode=1 sig_alg=6 ..."},
    {"name": "Entry index check", "ok": true,  "detail": "entry_index=1 is valid"},
    {"name": "Checkpoint cache",  "ok": false, "detail": "cache miss · fetching ..."},
    {"name": "Checkpoint fetch+verify", "ok": true, "detail": "issuer sig ✓ · 2/2 witnesses ✓"},
    ...
  ]
}
```

---

## Repository layout

```
mta-qr-demo/
├── SPEC.md                    # Protocol specification v0.1
├── ARCHITECTURE.md            # Code structure and design decisions
├── README.md                  # This file
├── test-vectors/
│   ├── README.md              # Vector format, how to add new ones
│   └── vectors.json           # Canonical fixtures (7 vectors)
├── go/
│   ├── shared/                # merkle, cbor, checkpoint, payload, signing
│   ├── issuer/                # HTTP server + in-memory log
│   └── verifier/              # HTTP server + 15-step verification engine
├── ts/
│   ├── shared/                # same five modules + signing
│   ├── issuer/                # HTTP server
│   └── verifier/              # HTTP server
├── browser-demo/              # Self-contained in-browser demo (no build, no server)
├── interop_test.py            # 15-test automated matrix (12 positive + 3 negative)
├── docker-compose.yml
└── docker/                    # go.Dockerfile, ts.Dockerfile
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for a detailed walkthrough of each component.

---

## Key facts

**CBOR:** Go uses `fxamacker/cbor/v2` with `CanonicalEncOptions()`. TypeScript uses `cborg` — `cbor-x` does not produce RFC 8949 §4.2 deterministic encoding for `Map` inputs with integer keys.

**Ed25519 in TypeScript:** Node.js built-in `crypto` via PKCS#8/SPKI DER key objects. No external Ed25519 dependency. Requires Node 18+.

**ECDSA P-256 wire format:** Raw r‖s (IEEE P1363), 64 bytes. Not DER. Both note signature lines and `issuer_sig` payload fields use this encoding.

**ML-DSA-44 (FIPS 204, `sig_alg=1`):** Go uses `cloudflare/circl v1.6.3`. TypeScript uses `@noble/post-quantum`. Both produce identical public keys from the same 32-byte seed, confirmed by the `signing-mldsa44` canonical vector. 2420-byte signatures, 1312-byte public keys.

**Tiled two-level Merkle tree:** The inclusion proof in each payload has two segments: an inner proof (entry → batch root, ≤4 hashes) and an outer proof (batch root → parent tree root, ≤4 hashes). `BATCH_SIZE=16`, `OUTER_MAX_BATCHES=16`. Maximum proof: 8 hashes = 256 bytes, regardless of total log size. The `inner_proof_count` byte in the payload encodes the split point. The checkpoint signs the **parent tree root**, not a flat root over all entries.

**Note format issuer signature dispatch:** Verifiers identify the issuer's signature line by matching the `issuer_key_name` field from the trust config against the key name prefix in note signature lines — not by byte length. Length-based heuristics break with ML-DSA-44 (2420 bytes vs. 64 bytes for Ed25519/ECDSA-P256).

**Witnesses always use Ed25519** regardless of issuer `sig_alg`. Per c2sp.org/tlog-cosignature. The demo generates two in-process witness keys per issuer instance for self-cosigning.

**No external witness network.** The demo self-cosigns. Production deployments would submit to the transparency.dev OmniWitness network.

---

## References

- [`SPEC.md`](SPEC.md) — protocol specification
- [draft-davidben-tls-merkle-tree-certs-09](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/)
- [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
- [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature)
- [transparency.dev](https://transparency.dev)
- [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) — Merkle hash tree
- [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) — CBOR deterministic encoding
