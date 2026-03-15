# MTA-QR Implementer's Guide

This document is a practical companion to SPEC.md. SPEC.md is normative — it
defines what implementations must do. This document is about what actually
trips people up when building one.

The four reference implementations (Go, TypeScript, Rust, Java) collectively
made every mistake described below. Most of them are not obvious from reading
the spec alone. Working code that fails against an independent implementation
is a better teacher, but this guide is faster.

---

## Contents

1. [Before You Start](#1-before-you-start)
2. [Signed-Note Wire Format](#2-signed-note-wire-format)
3. [CBOR Encoding](#3-cbor-encoding)
4. [Merkle Tree Implementation](#4-merkle-tree-implementation)
5. [Two-Level Tiled Tree](#5-two-level-tiled-tree)
6. [The Timestamp Bug](#6-the-timestamp-bug)
7. [Algorithm Dispatch](#7-algorithm-dispatch)
8. [Trust Configuration Lifecycle](#8-trust-configuration-lifecycle)
9. [Checkpoint Cache Keying](#9-checkpoint-cache-keying)
10. [Verification Flow — What to Stub and What to Implement](#10-verification-flow--what-to-stub-and-what-to-implement)
11. [Mode Selection](#11-mode-selection)
12. [Security Implementation Requirements](#12-security-implementation-requirements)
13. [Algorithm Deployment Status](#13-algorithm-deployment-status)
14. [Testing Strategy](#14-testing-strategy)
15. [What a Minimal Working Implementation Looks Like](#15-what-a-minimal-working-implementation-looks-like)

---

## 1. Before You Start

**Read the c2sp.org specs directly.** The three external specs that MTA-QR
builds on are:

- [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint) — checkpoint body format and signed-note conventions
- [c2sp.org/signed-note](https://c2sp.org/signed-note) — signature line format, key hash derivation
- [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) — witness cosignature message format

The MTA-QR SPEC.md reproduces the essential parts, but the c2sp specs are the
authoritative source for the wire format. Anything the SPEC says that contradicts
c2sp.org is a SPEC bug.

**Get the test vectors passing first.** The canonical vectors in
`test-vectors/vectors.json` cover every layer independently: checkpoint body
format, CBOR encoding, Merkle tree construction, entry hash computation, and
signing. A new implementation that passes all vectors against known-good output
has a solid foundation. An implementation that goes straight to end-to-end
testing with no layer isolation will be very hard to debug when something goes
wrong.

**Implement a verifier before an issuer.** The verifier's job is to reject
everything that's wrong, so it surfaces format bugs immediately. An issuer that
produces internally consistent but spec-non-compliant output will appear to work
until it's tested against an independent verifier.

---

## 2. Signed-Note Wire Format

This is where all four reference implementations had bugs initially. The
signed-note format has two properties that are easy to get wrong independently
and whose interaction makes debugging hard.

### Key hash derivation

The key hash is not a hash of the public key. It is a hash of a specific string
that includes the key name and a type identifier byte. For Ed25519:

```
key_hash = SHA-256(key_name || 0x0A || 0x01 || raw_pubkey)[0:4]
```

`0x0A` is a newline byte. `0x01` is the Ed25519 type identifier defined by
c2sp.org/signed-note. The formula is:

```
SHA-256("<name>\n\x01<32-byte-pubkey>")[0:4]
```

All four reference implementations initially computed
`SHA-256(name + "+" + base64(pubkey))`, which produces a different value for
the same key. This caused a particularly confusing failure mode: the issuer and
verifier agreed with each other (internally consistent wrong format) but would
not interoperate with any external tlog tooling.

For ECDSA P-256 and ML-DSA-44, the type byte differs. Check the c2sp.org/signed-note
spec for the registered type bytes. For algorithms without registered type bytes,
external interop is not possible yet — see Section 13.

For witness cosignature key IDs in the binary WitnessCosig struct, the same
formula applies. The 4-byte key_id in the struct uses the same derivation as
the key hash in the signature line.

### Signature line structure

Each signature line contains:

```
— <bare_key_name> <base64(4_byte_key_hash || raw_signature)>
```

The key hash is the first 4 bytes of the base64-decoded content, not a
separate field. The raw signature follows immediately. For Ed25519, the
base64 payload is 68 bytes (4 + 64). For ML-DSA-44, it is 2424 bytes (4 + 2420).

The common mistake is to put only the raw signature in the base64 field and
omit the 4-byte prefix. An issuer that does this and a verifier that expects
the same incorrect format will interoperate with each other but not with
anything else.

### Key name in the signature line

The signature line uses the bare key name only, not the full verifier key
string. The full verifier key string (which includes a hex key ID component,
used in note verifier configuration) goes in the trust config as
`issuer_key_name`, but the signature line itself contains only the bare name.

Example:
- Trust config `issuer_key_name`: `my-issuer+abcd1234+<base64(pubkey)>` (full verifier key string with hex key ID)
- Signature line key name: `my-issuer` (bare name only — no `+abcd1234+...`)

Wait — actually the c2sp.org/signed-note format uses a different convention.
Read the spec directly for the current definition. The reference implementation
in this repo demonstrates the correct format; compare `NoteKeyName()` vs the
full trust config `IssuerKeyName` field.

### Checkpoint body — the trailing newline

The checkpoint body is three lines, each terminated by `\n`, including the
final line. The trailing newline on the root hash line is part of the
authenticated content. Every implementation that strips trailing whitespace
before verifying signatures will fail, and this error is silent — the signature
verification just returns false with no indication that the input was wrong.

```
example.com/origin/v1\n
1234\n
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n
```

That final `\n` after the `=` is mandatory. Write a test that checks the exact
byte representation of a known-good checkpoint body.

### Note separator

The blank line between the checkpoint body and the signature lines is a double
newline: the `\n` ending the last body line, then another `\n` for the blank
line. When splitting a note on `\n\n`, the body ends immediately before the
double newline and the signature lines begin immediately after.

Parsers that accept checkpoint bodies with more than three lines (i.e., with
optional extension lines) should split on the first `\n\n` and treat the
content before it as the body. Parsers that require exactly three body lines
will reject checkpoints from real-world logs that add extension lines.

---

## 3. CBOR Encoding

### Library selection matters

Most CBOR libraries do not produce RFC 8949 §4.2 deterministic encoding by
default, and some do not support it at all. The failure mode is silent: the
encoding is valid CBOR that decodes correctly, but the entry hash computed from
it does not match what an issuer that uses canonical encoding would produce,
so the Merkle inclusion proof fails.

Known-good choices:
- Go: `fxamacker/cbor/v2` with `CanonicalEncOptions()`
- TypeScript/JavaScript: `cborg` (canonical by default). Not `cbor-x` — it does not
  produce canonical encoding for `Map` inputs with integer keys regardless of its
  `canonical` option.
- Rust: `ciborium` with the appropriate serialization mode, or `minicbor` with
  explicit field ordering.
- Python (for tooling): `cbor2` with `canonical=True`.
- Java: a CBOR library that supports canonical mode; verify with test vectors.

### Decoding: `useMaps: true`

When decoding with `cborg` in TypeScript, pass `{ useMaps: true }`. Without it,
`cborg.decode()` returns a plain JavaScript object for CBOR maps with integer
keys, and `.get(2)` on a plain object returns `undefined` silently. This
produces a valid-looking but empty decoded entry.

### Canonical encoding: what it actually means

RFC 8949 §4.2 deterministic encoding requires:
- Integer keys in maps sorted in ascending numeric order
- Definite-length encoding (no indefinite-length arrays or maps)
- No floating point values where integers suffice
- No duplicate map keys

The most common violation is map key ordering. Most libraries that claim
"canonical" mode get this right, but verify with the test vectors.

### Non-canonical CBOR presents as a Merkle failure

If the issuer encodes a valid entry but not in canonical form, the verifier
will compute a different entry hash from the same data and the inclusion proof
will fail. This is a Merkle root mismatch at the verifier, not a CBOR error.
The error message will say something like "root mismatch" with no indication
that the underlying cause is CBOR encoding. Diagnose by re-encoding the raw TBS
bytes through a known-good canonical encoder and comparing — if the bytes differ,
the encoding is wrong.

Add a round-trip test to your issuance pipeline: encode the entry, decode it,
re-encode with a reference canonical encoder, compare bytes.

### Field 1 is permanently reserved

The DataAssertionLogEntry CBOR map has fields 2, 3, and 4. Field 1 does not
exist and must not be added by any extension. Its absence is load-bearing: the
entry hash construction must produce identical results regardless of whether the
payload is in bound mode or self-describing mode, which means the CBOR entry
must not contain any field that varies between modes. If a future version needs
per-entry issuer identity, it must define a new entry type.

### Duplicate map keys

CBOR entries with duplicate map keys must be rejected at the CBOR decode step.
Do not rely on the hash mismatch to catch this — configure your CBOR library
to enforce `DupMapKeyEnforcedAPF` or equivalent. The reference Go verifier
initially used default decode options that silently accepted duplicate keys;
the Merkle proof failure would have been the only error signal.

---

## 4. Merkle Tree Implementation

### Domain separation bytes

Leaf nodes are hashed as `SHA-256(0x00 || data)`. Internal nodes are hashed as
`SHA-256(0x01 || left || right)`. These domain separation bytes prevent
second-preimage attacks where an attacker substitutes an internal node for a
leaf. Get this wrong and the tree produces wrong results silently.

### Left/right child determination

At each level of the proof, `entry_index % 2 == 0` means the current node is
a left child and its sibling (from the proof array) goes on the right:

```
node = SHA-256(0x01 || current || sibling)
```

`entry_index % 2 == 1` means the current node is a right child:

```
node = SHA-256(0x01 || sibling || current)
```

After combining, shift `entry_index` right by one (`entry_index >>= 1`) to
move to the next level. Getting the left/right ordering wrong produces wrong
roots for odd-indexed entries while even-indexed entries may still pass — an
easy bug to miss if your test data only covers entry 0 or entry 1.

### Proof array ordering

Sibling hashes are ordered from leaf to root. The first element in the proof
array is the sibling at the leaf level; the last element is the sibling at the
level just below the root. When verifying, iterate the array in order.

### Odd tree sizes

When the tree has an odd number of entries at some level, the last entry is
promoted (hashed with itself, or in this implementation handled by the batch
boundary logic). Get the handling of odd-count levels wrong and trees with
non-power-of-two sizes produce wrong roots. The test vector with a four-entry
tree covers only power-of-two sizes; test specifically with three-entry and
five-entry trees.

---

## 5. Two-Level Tiled Tree

This is the part of the implementation where the code diverges most from a
naive RFC 6962 implementation. Read this section carefully before writing any
code.

### What the checkpoint root actually is

The checkpoint root hash is NOT a flat Merkle root over all entry hashes. It is
a Merkle root over batch roots. The two-level structure is:

- **Inner level (batch):** each group of `BATCH_SIZE` entries forms its own
  Merkle tree. The root of that tree is the `batch_root`.
- **Outer level (parent):** the `batch_root` values are assembled into a second
  Merkle tree. The root of that tree is what gets signed in the checkpoint.

An implementation that builds a flat tree over all entries and signs it will
produce checkpoints that fail verification against any correct implementation.

### Two-phase proof verification

The inclusion proof in the QR payload is split into two consecutive segments
by the `inner_proof_count` field:

- **Phase A (inner proof):** `inner_proof_count` hashes from `entry_hash` to `batch_root`.
  The batch index and inner index are computed as:
  ```
  batch_index = entry_index / BATCH_SIZE
  inner_index = entry_index % BATCH_SIZE
  batch_size  = min(BATCH_SIZE, tree_size - batch_index * BATCH_SIZE)
  ```
  Walk `inner_proof_count` sibling hashes using `inner_index` as the starting
  index. The result is `batch_root`.

- **Phase B (outer proof):** the remaining `proof_count - inner_proof_count` hashes
  from `batch_root` to the parent root. The outer index is `batch_index`. Walk
  the remaining hashes using `batch_index` as the starting index. The result
  must equal the checkpoint `root_hash`.

The checkpoint root is what gets verified against the signed checkpoint, not an
intermediate batch root.

### BATCH_SIZE in the trust configuration

`BATCH_SIZE` is a deployment parameter. Issuers must emit it in the trust
configuration as `batch_size`. Verifiers that hardcode `BATCH_SIZE=16` will
silently misparse proofs from issuers using a different batch size. Load it
from the trust config; default to 16 only for backward compatibility with old
trust configs that predate the field.

### Entry index 0 is always null_entry

Index 0 of every log is a `null_entry` reserved placeholder. Verifiers must
reject any payload with `entry_index == 0` immediately, before consulting the
trust config or cache. A payload with `entry_index == 0` is structurally
invalid regardless of whether its proof is well-formed.

Issuers must log a `null_entry` at index 0 when initializing a new log. The
first real data assertion is at index 1.

---

## 6. The Timestamp Bug

This deserves its own section because it is the most insidious bug in the
reference implementations and the hardest to diagnose.

The `WitnessCosig` binary struct contains an 8-byte big-endian timestamp. When
serializing a 64-bit integer to big-endian bytes:

```
for i in 0..8:
    bytes[i] = (value >> (56 - 8*i)) & 0xFF
```

The shift amount decreases by 8 for each byte: 56, 48, 40, 32, 24, 16, 8, 0.

The common bug is to write:

```
for i in 0..8:
    bytes[i] = value & 0xFF
    value >>= 8      // wrong! shifts the source, doesn't use different bit positions
```

or equivalently to shift by 8 each iteration without first computing the right
starting position. This writes the low byte of the timestamp to all 8 positions
instead of the big-endian representation.

**The failure mode is specific:** the issuer signature check passes, the
inclusion proof passes, but the witness quorum check fails with `0/N witnesses
verified`. There is no other error signal. Everything looks correct except that
all cosignatures fail verification.

The timestamp must match exactly between:
1. The big-endian bytes in the binary `WitnessCosig` struct
2. The decimal ASCII string in the `cosignature/v1` signed message

Both must represent the same integer. Verify by decoding the big-endian bytes
back to an integer and formatting as decimal, then checking it matches what was
in the cosignature message.

---

## 7. Algorithm Dispatch

### Never dispatch by signature byte length

Ed25519 and ECDSA P-256 both produce 64-byte raw signatures. Any implementation
that dispatches by length will silently accept ECDSA signatures when Ed25519 is
expected, or vice versa. This is a security failure, not an interoperability
failure.

The algorithm comes from the trust configuration for the origin, not from the
payload. The `sig_alg` field in the payload flags byte must be checked against
the trust configuration and the payload rejected if they disagree. This check
prevents downgrade attacks.

For the verifier note parser, identify the issuer's signature line by matching
the `issuer_key_name` from the trust configuration against the key name prefix
in each `—` line. Once identified, dispatch verification using the `sig_alg`
from the trust configuration.

### Witness cosignatures are always Ed25519

Per c2sp.org/tlog-cosignature, witnesses sign with Ed25519 regardless of the
issuer's `sig_alg`. An ML-DSA issuer still has Ed25519 witnesses. The issuer
and witness trust domains are separate.

### Reject unrecognized sig_alg values

A payload with an unrecognized `sig_alg` value must be rejected immediately.
Do not attempt to verify it with a default algorithm or skip the algorithm
binding check.

### ECDSA signature encoding

ECDSA signatures in checkpoint note lines and in Mode 0 embedded fields must
use raw r‖s encoding (IEEE P1363), not DER/ASN.1. For P-256, the signature is
always exactly 64 bytes (r and s each padded to 32 bytes). Most ECDSA
implementations natively produce DER; converting to raw r‖s requires stripping
the DER wrapper and zero-padding each component to the field size.

---

## 8. Trust Configuration Lifecycle

### What the trust configuration contains

The trust configuration is the complete set of data a verifier needs before it
can verify any payload from an issuer:

- `origin`: the full UTF-8 origin string
- `origin_id`: hex of first 8 bytes of SHA-256(origin) — a routing hint
- `issuer_pub_key_hex`: hex-encoded issuer public key
- `issuer_key_name`: the note verifier key string used to locate the issuer's
  signature line in checkpoint notes
- `sig_alg`: the algorithm identifier
- `witnesses`: list of witness entries with name, key_id_hex, and pub_key_hex
- `witness_quorum`: minimum distinct cosignatures required
- `checkpoint_url`: where to fetch the cosigned checkpoint on cache miss
- `batch_size`: the tiled tree batch size; default 16 if absent

### Distribution model

The trust configuration is distributed out-of-band by the issuer. For a demo,
`GET /trust-config` from the issuer endpoint is convenient. For production, the
trust configuration is typically bundled with the verifier application or fetched
once at provisioning time from an authenticated configuration endpoint.

The trust configuration is not communicated in the QR payload. A verifier that
has not been provisioned with a trust configuration for an issuer cannot verify
that issuer's payloads.

### origin_id is a routing hint, not an identifier

The 8-byte `origin_id` is used only to find the right trust anchor quickly
without parsing the full origin string from every payload. It must not be used
as a cache key, a revocation key, or a security identifier. Two origins can
share an origin_id with probability roughly 1 in 2^64, which is negligible for
any realistic trust configuration size, but the verifier must check for
collisions at config-load time and reject configurations that have them.

### origin_id collision detection

When loading a new trust configuration, check whether any existing trust anchor
has the same 8-byte origin_id but a different full origin string. If so, reject
the new configuration with an error. Two different origins must not share an
origin_id, because the verifier routes by origin_id and a collision makes the
routing ambiguous. The check must happen at load time, not at verification time.

### Key rotation

Key rotation requires updating the trust configuration distributed to all
verifiers. The issuer generates a new key pair, publishes a new trust
configuration with the new key, and distributes it. The old key remains valid
until all outstanding payloads signed with it have expired. Issuers that need
simultaneous classical and PQC support use the `dual_sig` flag and include
both signatures in checkpoints, with both keys in the trust configuration.

---

## 9. Checkpoint Cache Keying

The checkpoint cache key must be `(full_origin_string, tree_size)`, not
`(origin_id, tree_size)`.

Two logs from the same issuer running different signing algorithms will produce
different `sig_alg` values and should have different origin strings. But if
they somehow share an origin_id (unlikely but possible), keying by origin_id
would cause the cache to serve the wrong Merkle root for one of them. The
failure would present as a Merkle root mismatch with no obvious cause.

Even in the common case where there is no collision, using origin_id as a cache
key is a latent bug waiting for a configuration that happens to produce a
collision. The full origin string is cheap to store. Use it.

---

## 10. Verification Flow — What to Stub and What to Implement

A minimal correct verifier implements Mode 1 verification. Mode 0 and Mode 2
are extensions. This section describes what's safe to stub and how to do it
honestly.

### Steps that must be implemented

- Payload decode and length bounds checking
- Entry index 0 rejection (immediately, before any other step)
- Trust anchor lookup by origin_id
- Self-describing origin consistency check
- Algorithm binding check (sig_alg from payload vs. trust config)
- Checkpoint fetch and cache (on cache miss)
- Issuer signature verification over checkpoint body
- Witness cosignature quorum verification
- Entry hash computation
- Two-phase Merkle inclusion proof
- Expiry check

### Steps that are legitimately stubbed in the reference implementation

**Revocation (step 9):** the revocation protocol is fully specified in SPEC.md §Revocation,
including the security model, authorization model, rollback resistance, and all
normative construction parameters. The reference implementations still stub this step:

```
add("Revocation check", true, "not implemented — no revocation list defined")
```

**Security model summary for implementers.** Read SPEC.md §Revocation — Security
Model before writing any code. Key points that affect implementation decisions:

- The issuer is the sole authority for R. There is no independent check that R
  is complete. This is a known limitation acknowledged in the spec.
- Signature verification happens at artifact load time, once. Cache the parsed
  cascade plus a SHA-256 hash of the raw bytes for in-memory integrity checks.
- Implement the staleness check: reject artifacts where
  `checkpoint.tree_size - artifact.tree_size > 2 * BATCH_SIZE`. An issuer that
  stops updating their revocation artifact will be detected.
- On first use for an origin, fetch both checkpoint and revocation artifact
  before accepting any payload. There is no safe baseline without both.
- An empty cascade (`num_levels=0`) is valid when R is empty. It is not
  distinguishable from a malicious empty artifact by cryptographic means alone.

**When implementing the cascade construction:**

The construction must be deterministic. Four things must be identical across all
implementations or test vectors will fail:

1. **Element encoding:** `entry_index` as 8-byte big-endian unsigned integer.
2. **Hash function:** `bit_position(x, i) = big_endian_uint64(SHA-256(x || uint8(i))[0:8]) mod m`
   where `x` is the 8-byte element and `i` is the level index (0-based).
3. **Bit array size:** `m = max(ceil(n * 1.44), 64)` rounded up to nearest multiple of 8.
4. **Insertion order:** ascending `entry_index` within each level.

**Bit encoding:** bit `i` in byte `i/8` at position `7 - (i mod 8)` (MSB-first).

**Query alternation:** Level 0 in-filter → tentatively revoked. Level 1 in-filter
→ false positive, not revoked. Level 2 in-filter → revoked again. If any level's
bit is 0, return current interpretation immediately.

**Binary format:** `uint8 num_levels` then per level `uint32 bit_count | uint8 k | bytes`
(all big-endian).

**Common implementation mistakes:**

- Little-endian element encoding or bit_count field
- Off-by-one in the bit array size formula (ceil vs floor)
- Inserting elements in non-ascending order
- LSB-first bit encoding instead of MSB-first
- Inverted query alternation at odd levels
- Verifying signature on every query instead of at load time
- Missing the staleness check (serving a stale artifact silently)
- Not checking `origin` in the artifact body against the expected origin

**Rejection cases your test suite MUST cover:** See SPEC.md §Test Vectors —
Revocation Vectors, cases R-REJ-1 through R-REJ-9.

**Implementation sequence:** Go cascade + test vectors → Rust → TypeScript → Java.
Generate test vector R1 bytes from Go, lock them, verify all other languages
reproduce the same bytes. See SPEC.md §Revocation for the full normative spec.

**Mode 0:** implement explicit rejection. A Mode 0 payload passed to a Mode 1
verifier must return a clear error, not silently fall through to the network
fetch path. Silently verifying a Mode 0 payload via the checkpoint endpoint
defeats Mode 0's design intent.

**Mode 2 inclusion proof:** the SDK verifier accepts Mode 2 payloads but does
not fetch or verify the inclusion proof, because the tile server API is not
yet defined. If your implementation does the same, document it clearly. The
result must indicate `mode=2` so callers can gate on it.

**key_assertion (Type 0x02):** the challenge-response protocol is schema-defined
and out of scope for this spec. Reject Type 0x02 entries with an explicit error
or mark the result with a clear "possession proof not implemented" status.

### What happens if you get stub behavior wrong

The most dangerous wrong stub is Mode 0 silent fallthrough. A verifier that
accepts a Mode 0 payload by fetching the checkpoint from the network has a
correct outcome only as long as the checkpoint endpoint is reachable and the
payload hasn't been tampered with since it was issued. But Mode 0 is supposed to
be verifiable offline without the checkpoint endpoint. An attacker who can make
the checkpoint endpoint unreachable can make Mode 0 verification fail; an
attacker who can replace the checkpoint response can make the verifier accept
tampered payloads. The silent fallthrough turns Mode 0 into a weaker version of
Mode 1, not the intended offline-capable mode.

---

## 11. Mode Selection

### Mode 1 is the general recommendation

Mode 1 gives you cryptographic verification of the inclusion proof with no
requirement for network access at scan time (after the initial checkpoint cache
is populated). The payload is compact and stable in size regardless of log
volume. Use Mode 1 unless you have a specific reason to use another mode.

### Mode 2 is for fixed-infrastructure deployments

Mode 2 produces the smallest possible payload (around 30 bytes). It requires
network access at scan time to fetch both the checkpoint and the inclusion proof.
Use it only in environments where connectivity at scan time is guaranteed and
the smallest QR code is a priority. Do not use Mode 2 where network access is
unreliable — a failed fetch means the QR cannot be verified at all.

Mode 2 and Mode 1 have identical security properties when both are fully
implemented. A Mode 2 payload whose inclusion proof has been fetched and
verified is just as strong as a Mode 1 payload. The difference is operational,
not cryptographic.

### Mode 0 is for fully offline deployments

Mode 0 embeds the inclusion proof and a compact cosigned checkpoint directly
in the QR payload. No network access is required at verification time — not
even for the initial checkpoint cache. A trust configuration (issuer and witness
public keys) must still be pre-loaded on the device.

Mode 0 payloads are significantly larger. With ECDSA P-256 and two witness
cosignatures, a minimal Mode 0 payload is around 700 bytes. With ML-DSA-44,
Mode 0 is not feasible within QR capacity limits.

Mode 0 is not yet implemented in this reference SDK.

### Payload size implications

| Mode | Algorithm | Approximate size | QR version |
|------|-----------|-----------------|------------|
| 1 | Any | 500-600 bytes | 15-20 (M ECC) |
| 2 | Any | ~30 bytes | 3-4 (M ECC) |
| 0 | ECDSA P-256 / Ed25519 | ~700 bytes | 18-20 (M ECC) |
| 0 | FN-DSA-512 | ~1300 bytes | 40 (M ECC, marginal) |
| 0 | ML-DSA-44 | ~3000 bytes | Not feasible |

Mode 1 payload size is stable over time regardless of log volume, because the
two-level tiled tree bounds the proof to a maximum of 8 hashes (256 bytes)
regardless of total entry count.

---

## 12. Security Implementation Requirements

These are the mistakes the reference implementations made that are reproducible
in any naive implementation.

### SSRF on trust config endpoints

If your verifier exposes an endpoint that accepts a URL and fetches a trust
configuration from it, restrict the permitted hosts. An unrestricted endpoint
allows an attacker to cause the verifier to probe internal network services,
hit cloud metadata endpoints (169.254.169.254), or load a malicious trust
configuration from an attacker-controlled server. The malicious trust config
can supply any `checkpoint_url` it likes, causing a second fetch to an
attacker-controlled endpoint.

The reference implementation restricts `/load-trust-config` to localhost targets
only. Production deployments should load trust configurations from disk or from
an authenticated provisioning service, not from user-supplied URLs.

### Body size limits

All inbound HTTP request bodies and all outbound HTTP response bodies must have
size limits. A valid checkpoint is around 200 bytes. A valid trust configuration
is a few kilobytes. A valid issue request is a few kilobytes. Setting a 64KB
limit on all of these is generous and safe.

Without limits: a slow POST to `/issue` with a gigabyte body will be buffered
entirely before parsing; a malicious checkpoint endpoint serving a gigabyte
response will exhaust verifier memory.

In Go: `http.MaxBytesReader(w, r.Body, 64*1024)` before decoding.
In Node.js: track accumulated length in the `data` handler and destroy the
stream when it exceeds the limit.
In Rust: read bytes and check length before converting to string.
In Java: use `BodyHandlers.ofByteArray()` and check length before use.

### HTTP client timeouts

All outbound HTTP requests must have timeouts. A slow or hanging issuer
endpoint will hold the handler goroutine or task indefinitely without a timeout.
With a retry loop (the reference implementation retries trust config auto-load
10 times), this becomes a sustained resource leak.

Checkpoint fetches: 10 seconds is a reasonable timeout.
Trust config fetches: 10 seconds.
Witness submissions: 10 seconds.

In Go: `&http.Client{Timeout: 10 * time.Second}`.
In Node.js: `fetch(url, { signal: AbortSignal.timeout(10_000) })`.
In Rust: `reqwest::Client::builder().timeout(Duration::from_secs(10)).build()`.
In Java: `HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()`.

### XSS in verifier UI

If your verifier has a browser UI that displays verification results, do not
use `innerHTML` with any content derived from the verified payload. Claim keys,
claim values, step names, step details, origin strings, and checkpoint URLs are
all attacker-controlled. A QR code with `<img src=x onerror=alert(1)>` as a
claim value will execute in the verifier's browser context if you render claims
via `innerHTML`.

Use `textContent` or `createElement`/`appendChild` for all user-controlled
content. The only safe content for `innerHTML` is static strings that you wrote
and that contain no user input.

### CORS on state-mutating endpoints

If your verifier has an endpoint that modifies server state (such as loading
a new trust configuration), do not set `Access-Control-Allow-Origin: *` on that
endpoint. A wildcard CORS policy on a state-mutating endpoint allows any web page
to trigger the mutation from any visitor's browser. Combined with an SSRF
vulnerability, this creates a browser-triggered SSRF chain.

Set `Access-Control-Allow-Origin: null` (or restrict to a known origin) on any
state-mutating endpoint. Read-only endpoints can use wildcard CORS.

### Witness identification

When parsing a checkpoint note, identify witness signature lines by matching
the 4-byte key hash from the base64 payload against the key hashes of known
witness keys in the trust configuration. Do not identify witness lines by
byte length alone. A malicious checkpoint server could construct a line with a
76-byte payload that isn't a cosignature but passes a length-based filter.

---

## 13. Algorithm Deployment Status

Not all `sig_alg` values can be used in production today.

### What works end-to-end today

**Ed25519 (`sig_alg=6`)** is the recommended starting algorithm. It has a
complete C2SP note signature type registration, works with external tlog
tooling (the witness network, `golang.org/x/mod/sumdb/note`, transparency.dev
infrastructure), and the WebCrypto Ed25519 API is available in modern browsers
and runtimes.

### What is implemented but blocked on C2SP registration

**ECDSA P-256 (`sig_alg=4`)** is implemented in all four reference
implementations but requires a C2SP note signature type registration before
checkpoint notes can be parsed by external tools. The registration must specify
the key name format, key hash derivation, and signature encoding. Until that
registration exists, ECDSA P-256 checkpoint signatures cannot be verified by
any tool that follows c2sp.org/signed-note.

**ML-DSA-44 (`sig_alg=1`)** is in the same position. All four implementations
include it, but external interop with the tlog witness network requires a
registered type byte.

**FN-DSA-512 (`sig_alg=0`), ML-DSA-65 (`sig_alg=2`), SLH-DSA-SHA2-128s (`sig_alg=3`)**
are defined in the spec but not implemented in any reference implementation.

### Recommended progression

Start with Ed25519. It works, it's fast, it has no external dependencies, and
the QR payload size is the same as ECDSA P-256. When you need post-quantum
resistance and the C2SP registration for ML-DSA or FN-DSA is complete, migrate
using the `dual_sig` flag to support both classical and PQC verifiers during
the transition.

---

## 14. Testing Strategy

### Layer-isolated unit tests

Test each layer independently before testing the whole stack:

1. CBOR encoding: encode a known entry, check bytes against the test vector.
2. Entry hash: compute `SHA-256(0x00 || tbs)`, check against the test vector.
3. Merkle tree: build a four-entry tree, check all internal node hashes and the
   root against the test vectors. Verify the inclusion proof for entry 2.
4. Checkpoint body: format a checkpoint body from known inputs, check bytes.
5. Key hash: compute the Ed25519 key hash from a known key, check result.
6. Signing: sign the checkpoint body from the test vector with the test key,
   check signature against the test vector (Ed25519 is deterministic).
7. Witness cosignature: build a cosignature/v1 message, sign it, verify the
   result.

If all layer tests pass, end-to-end tests fail only for integration-level
reasons, which are much easier to diagnose.

### Cross-implementation interop testing

Test your implementation against at least one independent implementation that
you know to be correct. The reference implementations in this repository are
the starting point. An issue payload from the Go HTTP service should verify
against your verifier, and vice versa.

The interop test matrix covers three algorithms across four implementations:
96 cells. Running it from scratch requires only Python 3 and the Go toolchain.

### Negative testing

Test that your verifier rejects:
- `entry_index == 0`
- Mismatched `sig_alg` between payload and trust config
- Tampered root hash (one bit flipped in the checkpoint root)
- Wrong witness key (cosignature from a key not in the trust config)
- Expired assertion (expiry_time in the past, no grace period)
- Malformed CBOR (truncated, or with an invalid map key)
- Inclusion proof that doesn't lead to the checkpoint root

At least one test per rejection case. The reference test suite includes a
"tampered payload" test that flips bytes in the proof path and verifies the
verifier rejects it.

---

## 15. What a Minimal Working Implementation Looks Like

If you want to implement a verifier that's correct for the common case before
handling every edge, here is what "minimal correct Mode 1 verifier" means:

**Inputs:** a binary MTA-QR payload and a pre-loaded trust configuration.

**Steps:**
1. Decode the binary payload per the struct in SPEC.md. Bounds-check every
   length field before reading.
2. Reject if `entry_index == 0`.
3. Look up the trust anchor by `origin_id`. Reject if not found.
4. If `self_describing`, verify the envelope origin matches the trust anchor origin.
5. Verify `sig_alg` from payload matches `sig_alg` in trust anchor. Reject on mismatch.
6. Fetch the checkpoint note from the trust anchor's `checkpoint_url`. Parse the
   checkpoint body (three lines, trailing newlines). Verify the issuer signature
   over the body using the public key and algorithm from the trust anchor. Verify
   at least `witness_quorum` distinct Ed25519 witness cosignatures from keys in
   the trust anchor. Cache `(full_origin, tree_size)` → root_hash.
7. Compute `entry_hash = SHA-256(0x00 || tbs)`.
8. Verify the two-phase Merkle proof: Phase A from entry_hash to batch_root
   (inner_proof_count hashes), Phase B from batch_root to root_hash (remaining
   hashes). Reject on mismatch.
9. (Stub): note that revocation is not checked.
10. Verify `expiry_time + 600 > current_unix_time`. Reject if expired.
11. Decode `entry_type_byte`. For 0x01 (data assertion): decode the CBOR entry
    and return the claims.

**Not in scope for the minimal implementation:**
- Mode 0 (reject with clear error)
- Mode 2 (tile fetching not implemented — note this clearly in the result)
- key_assertion Type 0x02 (reject with clear error)
- Revocation (document the stub)

A verifier that does all of the above correctly passes the interop matrix for
Mode 1 data assertions against any correct issuer.

---

## Appendix: Common Failure Modes and Diagnostics

| Symptom | Most likely cause |
|---------|------------------|
| All cosignatures fail; issuer sig passes | Timestamp big-endian serialization bug (Section 6) |
| Merkle root mismatch for all payloads | Using flat tree root instead of parent tree root (Section 5) |
| Merkle root mismatch for odd-indexed entries only | Left/right child ordering reversed (Section 4) |
| Merkle root mismatch with no crypto error | Non-canonical CBOR encoding (Section 3) |
| Entry hash mismatch | Domain separation byte wrong (0x00 prefix missing) |
| "key not found" for known witness | Key hash derivation formula wrong (Section 2) |
| Issuer sig fails externally; passes internally | Key hash prefix missing from note signature payload (Section 2) |
| Signature verification fails after checkpoint strip | Trailing newline stripped from checkpoint body (Section 2) |
| CBOR decode returns empty fields | `useMaps: true` missing in cborg decode call (Section 3) |
| Checkpoint body accepted with wrong root | Cache key using origin_id instead of full origin (Section 9) |

