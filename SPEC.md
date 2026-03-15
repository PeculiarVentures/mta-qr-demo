# MTA-QR: Merkle Tree Assertions for Verifiable QR Codes
## Design Draft v0.1

**Derived from:** draft-davidben-tls-merkle-tree-certs-09  
**Checkpoint format:** c2sp.org/tlog-checkpoint  
**Witness protocol:** c2sp.org/tlog-witness, c2sp.org/tlog-cosignature  
**Cryptography:** PQC-ready (FIPS 204, 205, 206); classical profile (ECDSA P-256/P-384, Ed25519) supported for transition deployments

---

## Problem Statement

Any system that acts on the contents of a QR code — admitting entry, dispensing
a drug, releasing goods, granting access — needs cryptographic assurance that
the QR code was produced by a legitimate issuer and hasn't been modified. That
assurance needs to hold in a post-quantum world.

Naive per-assertion signing fails on two constraints that compound together:

**Size.** A Version 40 QR code at Medium ECC has a raw data capacity of
1,273 bytes, but QR binary mode encoding overhead (mode indicator, character
count, padding) consumes 20–40 bytes, leaving approximately 1,230–1,250 bytes
of usable payload. ML-DSA-44 (FIPS 204, the smallest standardized lattice
signature) produces 2,420-byte signatures. It doesn't fit. FN-DSA-512 (FIPS
206) produces signatures up to 666 bytes and sits at the absolute boundary of
what Version 40 can carry — but embedding a full signature per assertion leaves
almost no room for assertion content, and permanently binds the QR code to a
specific key and algorithm at issuance time with no agility path.

**Offline verification.** QR scanning happens without reliable network access.
A design requiring a network call per scan fails at concert venues, border
crossings, pharmacy counters, warehouse receiving docks, and transit gates.

MTA-QR resolves both constraints by separating authentication overhead from the
per-assertion payload. A batch of N assertions shares one set of cosignatures
over a Merkle tree checkpoint. Each QR code carries only the entry's inclusion
proof — O(log N) hashes — plus the assertion content. Verification requires
only the inclusion proof and a locally cached checkpoint with cosignatures.

---

## The Charge Cycle Observation

The conventional framing for offline QR verification treats network access as a
binary property: either the verifier is connected at scan time, or it isn't.
This is the wrong frame.

Every device with a battery has a predictable, regular window where it is
stationary, connected to power, and likely on a network. This is when background
sync happens for everything else — app updates, map tiles, email. A checkpoint
is trivially small compared to any of these. Fetching a new tree head during a
charge cycle costs nothing operationally.

This applies to purpose-built readers and to phones equally. A turnstile charges
between events. A pharmacy scanner charges overnight. A phone charges every night.
The charge cycle is a reliable prefetch window regardless of the device type.

The design parameter that actually matters is **checkpoint staleness relative to
assertion issuance time**. If the verifier's cached checkpoint predates a given
log entry, the inclusion proof for that entry won't verify — the entry isn't in
that tree yet. So the question is: was the assertion issued before or after the
verifier's last checkpoint fetch?

For most use cases the answer is comfortably before: a ticket bought days before
an event, a prescription filled that morning, a badge issued at enrollment. A
verifier that fetches a checkpoint during its last charge cycle will have a tree
head that covers virtually all assertions it will encounter during the next
operational period.

The narrow failure case — assertion issued and scanned on the same device charge
cycle, before a checkpoint fetch has occurred — falls back to a single cache-miss
network call on first scan of that batch. One round-trip then covers every
subsequent scan of the same batch for the remainder of the charge cycle.

This means the design has no hard dependency on scan-time connectivity. It
degrades gracefully: prefetch during charge makes the common case fully offline,
and cache-miss fallback handles the edge case when connectivity is available.

---

## Use Cases

MTA-QR is a general authentication layer for any QR code that initiates a
consequential action. The authentication question — was this produced by a
legitimate issuer and is it unmodified? — precedes and is independent of any
business logic applied to the assertion's content.

**Event entry and ticketing.** Tickets, passes, boarding documents. The reader
verifies issuer authenticity before honoring the seat or fare assignment.

**Identity documents.** Driver's licenses, government IDs, permits. The reader
needs to know the document came from a recognized issuing authority before
relying on the fields it contains.

**Pharmaceutical and supply chain.** Drug packaging, medical device tracking,
luxury goods authentication. Scanners authenticate provenance before goods are
accepted, dispensed, or released.

**Border and immigration.** Travel documents, visas, crossing permits. Readers
may operate with intentionally limited connectivity; periodic sync is
operationally standard.

**Access control.** Building badges, vehicle passes, equipment authorization.
Readers at physical access points verify issuer authenticity before acting on
the access policy encoded in the assertion.

**Rotating membership and subscription cards.** Membership systems that rotate
QR codes on a short timer — to defeat screenshot-based fraud — are currently
doing this with no cryptographic authentication. The rotation is a mechanical
freshness mechanism that breaks as soon as the generation algorithm is
reverse-engineered. MTA-QR replaces the timer model with a cryptographically
sound one: the issuer produces short-lived data assertions, each a distinct log
entry with a distinct inclusion proof. A reader with a warmed checkpoint cache
verifies any currently-valid assertion entirely offline. The QR changes not
because of a clock but because each issuance is a new entry in an
append-only log that the issuer cannot retroactively modify.

**Any issued authorization.** Inspection certificates, safety compliance tags,
professional certifications. The pattern is always the same: an issuer makes an
assertion about something, a reader needs to verify that assertion before acting
on it, and the verification must be robust against forgery and future quantum
attack.

---

## Trust Model

The trust model is deliberately simpler than WebPKI.

A reader is configured with one thing: a set of trusted issuers. Each trusted
issuer entry is a tuple:

```
(origin, issuer_public_key, sig_alg, witness_quorum_policy)
```

`origin` is the full UTF-8 log origin string. An origin MUST uniquely identify
a single log instance, including its signing key and algorithm. Two log instances
operated by the same entity but using different signing keys or different
`sig_alg` values MUST use distinct origin strings. Deployments running multiple
algorithm variants in parallel (e.g., during a transition period) MUST use
distinct origins for each variant — for example `example.com/access/ed25519/v1`
and `example.com/access/ecdsa-p256/v1`.

`issuer_public_key` is the public key whose signature on a checkpoint makes that
checkpoint authoritative for this issuer. `sig_alg` is the algorithm identifier
(matching the values in the payload flags byte) that the verifier expects this
issuer to use. `witness_quorum_policy` is the minimum number of distinct trusted
witness keys that must have cosigned a checkpoint before the reader accepts it.

**Algorithm binding is a security requirement.** The verifier MUST check that
the `sig_alg` value in the received payload matches the `sig_alg` recorded in
its trust configuration for that origin. A verifier that accepts any algorithm
for a given origin is vulnerable to downgrade attack: an attacker who can
substitute a payload can claim a weaker algorithm than the issuer actually uses,
potentially reducing the security level to one the attacker can break. A
verifier MUST NOT use signature byte length to infer the signing algorithm.
Ed25519 and ECDSA P-256 raw signatures are both 64 bytes. Any implementation
that dispatches by length will silently accept ECDSA signatures when Ed25519 is
expected, or vice versa — a security failure, not merely an interoperability
failure. The algorithm MUST be obtained exclusively from the trust configuration
for the origin, never derived from payload fields.

**origin_id collision in trust configuration.** Verifiers MUST reject trust
configurations in which two or more trusted issuers produce the same 8-byte
`origin_id` (truncated SHA-256 of their origin strings). Such a collision makes
origin-based routing ambiguous and could cause a verifier to validate an
assertion against the wrong issuer's key. The probability of a collision in
any realistic trust configuration is negligible (2^64 space), but the condition
MUST be detected and rejected at configuration load time rather than silently
producing incorrect routing behavior at scan time.

There are no certificate chains, no root stores, no path building,
no subordinate relationships. The issuer is the trust anchor. The checkpoint
signature binds the origin string to the issuer key — a checkpoint from origin
X signed by key Y using algorithm Z is only valid in a reader whose trust
configuration contains the tuple (X, Y, Z, ...).

An assertion is valid if:

1. The inclusion proof places the log entry in a checkpoint signed by a trusted
   issuer key for the claimed origin.
2. The checkpoint has been cosigned by a sufficient quorum of witnesses per the
   trust configuration's quorum policy.
3. The assertion has not expired.
4. The entry index is not in the revoked set per the issuer's revocation artifact.

That's the entire verification algorithm. Nothing else is required.

The witness quorum provides transparency: it ensures the issuer cannot present
a different view of the log to different verifiers. A cosignature is a
cryptographic statement by the witness that it verified the new checkpoint is
consistent with all previous checkpoints it has seen for that log — that the
log is append-only from the witness's perspective. This is not a behavioral
assumption; it is what the c2sp.org/tlog-witness protocol enforces. The witness
verifies the consistency proof before cosigning, and the cosignature itself is
the proof that verification occurred. A verifier holding a checkpoint with a
valid quorum of witness cosignatures has everything it needs to verify
cryptographically offline — it does not need to contact witnesses at scan time
or trust that they will continue to behave.

Witnesses do not, however, control what the issuer chooses to log, prevent
entries from expiring, or guarantee that a verifier's checkpoint cache is
current. The transparency guarantee is specifically that the log is append-only
and fork-free as attested by the witness cosignatures.

Witnesses do not grant the issuer authority. They police the issuer's behavior
against the log they operate. Authority comes entirely from the reader's trust
configuration tuple.

**Monitoring and transparency for data assertions.** In Certificate
Transparency, domain owners monitor logs for unauthorized certificate issuance
against their names — there is a clear external party with a monitoring
interest independent of the issuer. For Type 0x01 data assertions (bearer
tokens), the monitoring story is different: the issuer is typically the only
party with a meaningful stake in detecting unauthorized entries, since data
assertions are about objects and events rather than named entities. The
transparency guarantee here is therefore primarily operational. Deployments
where independent monitoring is desired should define a schema that includes a
named subject field and publish a monitoring interface for that subject
namespace.

**Deploying an issuer** requires no negotiation with any root program. The
issuer generates a key pair, operates a log, publishes their origin string and
public key, and distributes that configuration to the readers they manage. The
witness network is available as shared public infrastructure; the issuer does
not need to run witnesses themselves.

---

## Cryptography

MTA-QR is algorithm-agnostic at the structural level. The Merkle tree, CBOR
entry format, checkpoint format, and witnessing protocol are identical
regardless of which signing algorithm the issuer uses. The `sig_alg` field in
the payload flags byte identifies the issuer's algorithm so verifiers know
which key and signature type to use when validating the checkpoint.

### Supported Issuer Algorithms

| Value | Algorithm | Sig size | WebCrypto? | Quantum-resistant? | Reference impl |
|-------|-----------|----------|------------|-------------------|----|
| 0 | FN-DSA-512 (FIPS 206) | up to 666 bytes, typ. 600–650 | No | Yes | — |
| 1 | ML-DSA-44 (FIPS 204) | 2,420 bytes (fixed) | No | Yes | ✓ Go, TypeScript, Rust, Java |
| 2 | ML-DSA-65 (FIPS 204) | 3,309 bytes (fixed) | No | Yes | — |
| 3 | SLH-DSA-SHA2-128s (FIPS 205) | 7,856 bytes (fixed) | No | Yes | — |
| 4 | ECDSA P-256 | 64 bytes (raw r‖s, IEEE P1363) | ✓ Yes | No | ✓ Go, TypeScript, Rust, Java |
| 5 | ECDSA P-384 | 96 bytes (raw r‖s, IEEE P1363) | ✓ Yes | No | — |
| 6 | Ed25519 | 64 bytes | ✓ Modern | No | ✓ Go, TypeScript, Rust, Java |

Unrecognized `sig_alg` values MUST be rejected.

**ECDSA wire format.** ECDSA P-256 and P-384 signatures in checkpoint note
signature lines and in Mode 0 embedded `issuer_sig` fields MUST use fixed-width
raw r‖s encoding (IEEE P1363): r and s each zero-padded to 32 bytes (P-256) or
48 bytes (P-384) big-endian, concatenated. DER/ASN.1 encoding MUST NOT be used.
The fixed-width format removes ambiguity in the note parser, where signature
bytes have no length prefix. For P-256, `issuer_sig` is always 64 bytes; for
P-384, 96 bytes.

**ECDSA public key encoding** in trust configuration `issuer_pub_key_hex` and
in note verifier key names: uncompressed point, `0x04 ‖ X ‖ Y`, 65 bytes for
P-256 (97 bytes for P-384), hex-encoded in the trust config field and
base64-encoded in the key name component. Compressed encoding is not required
to be supported.

SHA-256 — used for all Merkle hashing, entry hashing, and key_id derivation —
is available in every WebCrypto implementation. All verification logic except
issuer signature verification is therefore WebCrypto-compatible regardless of
which `sig_alg` the issuer chooses.

FN-DSA (Falcon) produces variable-length compressed signatures. The
`issuer_sig_len` field accommodates this variability. Size calculations should
use the maximum for worst-case budget analysis and typical sizes for
expected-case analysis.

During transition, issuers MAY produce dual signatures on checkpoints — a
classical signature for current verifiers and a PQC signature for
quantum-ready verifiers — carried as separate note signature lines on the
same checkpoint body. The `dual_sig` flag in the payload header signals that
the checkpoint for this payload carries a dual signature. In Mode 0, the
embedded `issuer_sig` is the primary algorithm only; `dual_sig` is a
checkpoint-level concern, not a per-QR-payload one.

**Verifier behavior during transition.** A verifier MUST validate the
signature corresponding to its configured `sig_alg` for the issuer. When
`dual_sig=1`, a verifier whose trust configuration has been updated to the
new algorithm MUST validate the new signature and SHOULD ignore the old
signature if it no longer holds the old public key. A verifier that still
holds only the old public key MUST validate the old signature and MAY ignore
the new. A verifier that holds both public keys MAY validate both and MUST NOT
pass a checkpoint where neither validates. The issuer MUST NOT retire the old
key from their checkpoint until all verifiers in their deployment have received
updated trust configurations pointing to the new key.

### WebCrypto Coverage by Operation

| Operation | API | Universal? |
|-----------|-----|------------|
| SHA-256 (hashing) | `crypto.subtle.digest` | ✓ Yes |
| Merkle inclusion proof | `crypto.subtle.digest` | ✓ Yes |
| ECDSA P-256 verify | `crypto.subtle.verify` | ✓ Yes |
| ECDSA P-384 verify | `crypto.subtle.verify` | ✓ Yes |
| Ed25519 verify (witness cosigs) | `crypto.subtle.verify` | ✓ Modern (Chrome 113+, Firefox 130+, Safari 17+) |
| FN-DSA / ML-DSA / SLH-DSA verify | — | ✗ Bring-your-own (WASM) |

---

## Checkpoint Format and Witness Integration

### Log Checkpoints

The issuer's log publishes checkpoints in c2sp.org/tlog-checkpoint format. A
checkpoint is a signed note consisting of a body and one or more signature
lines separated by a blank line.

**Checkpoint body** (the authenticated content — what all signatures are over):

```
<origin>\n
<tree_size decimal>\n
<root_hash_base64>\n
```

The body is exactly three lines, each terminated with `\n`, including the
final line. The trailing newline on the root hash line is part of the
authenticated content. Implementations that strip trailing whitespace before
verifying signatures will fail. The root hash is base64-encoded per RFC 4648 §4
(standard alphabet, with `=` padding, no line breaks — the exact base64
encoding matters for signature verification).

**Full served note** (body + blank line + signature lines):

```
<origin>
<tree_size decimal>
<root_hash_base64>

— <issuer_key_name> <base64(4_byte_key_hash || issuer_signature)>
— <witness_name_1> <base64(4_byte_key_hash || 8_byte_timestamp || 64_byte_ed25519_sig)>
— <witness_name_2> <base64(4_byte_key_hash || 8_byte_timestamp || 64_byte_ed25519_sig)>
```

The blank line between body and signatures is the note separator. Signature
lines begin with `— ` (em dash, space).

**Signed-note signature line format.** Per c2sp.org/signed-note, each signature
line carries: the key's bare human name (no key hash or public key embedded in
the line itself), a space, and a base64-encoded payload whose first 4 bytes are
the key hash (a routing hint identifying which trusted key produced this
signature) followed by the raw signature bytes.

**Key hash derivation (Ed25519).** Per c2sp.org/signed-note:
```
key_hash = SHA-256(key_name || 0x0A || 0x01 || raw_ed25519_pubkey)[0:4]
```
where `0x0A` is a newline byte and `0x01` is the Ed25519 signature type
identifier byte. The key hash is 4 bytes of a routing hint, not a
cryptographically strong identifier.

**The issuer note signature** is computed over the checkpoint body only — the
three-line body including its trailing `\n`. The base64 payload in the issuer
signature line is `key_hash(4) || raw_issuer_sig(N)` where N depends on
`sig_alg` (64 for Ed25519/ECDSA P-256, 2420 for ML-DSA-44).

When verifying an issuer signature, the verifier MUST determine the signing
algorithm from its trust configuration for the origin identified by `origin_id`
— not by inspecting the key name, not by measuring the signature byte length,
and not by attempting multiple algorithms. The verifier locates the issuer
signature line by matching the bare issuer key name from the trust config as a
substring of the line, decodes the base64 payload, discards the first 4 bytes
(key hash), and verifies the remaining bytes as the raw signature.

For ECDSA P-256 and FN-DSA, the key hash derivation and key name registration
require C2SP registration — see Open Questions.

### Witness Cosignatures

Witnesses apply cosignatures per c2sp.org/tlog-cosignature/v1. The signed
message is:

```
cosignature/v1\n
time <unix_timestamp_decimal>\n
<checkpoint body>
```

where `<checkpoint body>` is the exact three-line body including its trailing
`\n`. The timestamp is a decimal Unix timestamp in seconds.

Each cosignature in a checkpoint note signature line is a 76-byte payload:
4-byte key hash (per the signed-note format), 8-byte big-endian Unix timestamp,
and 64-byte Ed25519 signature over the cosignature/v1 message. In the Mode 0
binary `WitnessCosig` struct the same three fields appear in the same order.
**Witness cosignatures MUST use Ed25519 regardless of the issuer's `sig_alg`.**
Witness keys are independent of the issuer key; they do not inherit the issuer's
algorithm. This follows c2sp.org/tlog-cosignature, which specifies Ed25519 as
the only cosignature algorithm. The `WitnessCosig.signature` field is always
64 bytes.

The timestamp in the signed message and the timestamp in the binary
`timestamped_signature` MUST be identical; a mismatch is a verification failure.
When serializing the 8-byte big-endian timestamp from a language integer type,
implementations MUST shift the value right by 8 bits after extracting each byte.
A loop that extracts `value & 0xFF` eight times without shifting writes the low
byte to all 8 positions, not the big-endian representation. When this bug is
present, all witness cosignatures fail verification and the quorum check fails
with `0/N witnesses verified`; the issuer signature check passes and provides no
diagnostic signal.

The trust division is intentional: the issuer's signature (per `sig_alg`)
provides authenticity. The Ed25519 witness quorum provides transparency.
Compromising the transparency guarantee requires compromising multiple
independent witness operators simultaneously, which is a different and harder
attack than breaking a single issuer key.

### Witness Protocol

The issuer submits new checkpoints to witnesses per c2sp.org/tlog-witness:

```
POST <witness_submission_prefix>/add-checkpoint

old <previous_tree_size>
<consistency_proof_hash_base64>
...

<new_checkpoint_body>

— <issuer_signature_line>
```

The witness verifies the consistency proof from its stored previous checkpoint,
then returns a cosignature/v1 note signature line suitable for appending to the
checkpoint note. The issuer collects cosignatures from a configured quorum
before assembling QR payloads for that batch.

### tlog-tiles Entry Format

The log is served per c2sp.org/tlog-tiles. Each entry in a data tile is:

```
entry_type_byte || CBOR(AssertionLogEntry)
```

This is identical to the `tbs` field in the QR payload. The entry hash is
`SHA-256(0x00 || tile_entry)`. Log monitors and auditors fetch data tiles,
compute entry hashes from tile entries, and can independently verify that those
hashes are consistent with published checkpoints. Implementations MUST store
and serve this pre-hash content in data tiles. Storing computed `entry_hash`
values instead is wrong and prevents independent auditing.

---

## Payload Format

Binary encoding, big-endian integers, UTF-8 strings.

```
struct MTAQRPayload {
    uint8  version;          // 0x01
    uint8  flags;            // bits 0-1: mode (0=embedded, 1=cached, 2=online)
                             // bits 2-4: sig_alg
                             //   0=FN-DSA-512  1=ML-DSA-44   2=ML-DSA-65
                             //   3=SLH-DSA-128s
                             //   4=ECDSA-P256  5=ECDSA-P384  6=Ed25519
                             //   unrecognized values MUST be rejected
                             // bit  5:   dual_sig
                             // bit  6:   reserved
                             // bit  7:   self_describing (0=bound, 1=self-describing)
    uint64 origin_id;        // first 8 bytes of SHA-256(origin UTF-8); routing hint only
    uint64 tree_size;        // checkpoint tree size
    uint64 entry_index;      // log entry index (0 is reserved; MUST be rejected by verifiers)

    // Self-describing mode only:
    uint16 origin_len;
    byte   origin[origin_len];

    uint8  proof_count;      // total number of 32-byte hashes in inclusion proof
                             // Mode 2: proof_count = 0
    uint8  inner_proof_count; // hashes belonging to the inner (batch-level) proof
                             // The remaining proof_count − inner_proof_count hashes
                             // are the outer (parent tree) proof.
                             // Both segments use RFC 6962 sibling-hash ordering (leaf → root).
    byte   proof[proof_count * 32]; // inner_proof ++ outer_proof concatenated
    uint16 tbs_len;
    byte   tbs[tbs_len];     // entry_type_byte || CBOR(AssertionLogEntry)

    // Mode 0 only — compact embedded checkpoint:
    byte   root_hash[32];
    uint16 issuer_sig_len;   // ECDSA P-256: always 64; ECDSA P-384: always 96
    byte   issuer_sig[issuer_sig_len];  // raw r‖s (IEEE P1363), never DER
    uint8  witness_count;
    WitnessCosig cosigs[witness_count];
}

struct WitnessCosig {
    uint32 key_id;        // 4-byte key ID (SHA-256(key_name)[0:4])
    byte   timestamp[8];  // big-endian uint64 Unix seconds — same value used
                          // as decimal ASCII in the cosignature/v1 signed message.
                          // Serialization: shift value right 8 bits after each byte.
                          // Failing to shift produces all-same low byte in all 8
                          // positions; presents as "0/N witnesses verified".
    byte   signature[64]; // Ed25519 — always Ed25519 regardless of issuer sig_alg
}
```

`origin_id` is the first 8 bytes of SHA-256(origin UTF-8 string), stored as a
big-endian uint64. It is a routing hint only — verifiers use it to select the
correct trust anchor and cached checkpoint before parsing the TBS. The full
origin string in the cosigned checkpoint is the authoritative identifier.

**WitnessCosig key_id derivation.** The 4-byte `key_id` uses the same formula
as the signed-note key hash for Ed25519 keys:
```
key_id = SHA-256(key_name || 0x0A || 0x01 || raw_ed25519_pubkey)[0:4]
```
where `0x0A` is a newline byte and `0x01` is the Ed25519 signature type
identifier byte. This is not hex-encoded in the struct — it is the raw 4 bytes.
Verifiers map the 4-byte `key_id` back to a full witness public key via their
trust configuration. Collisions in the 4-byte `key_id` space within a single
verifier's trust configuration MUST be rejected. Total: 76 bytes per witness.

**Parser safety — length field bounds.** Parsers MUST verify that each declared
length does not exceed the number of bytes remaining in the payload buffer before
reading any variable-length field:

- Before reading `origin[origin_len]`: verify `origin_len ≤ remaining_bytes`.
- Before reading `proof[proof_count * 32]`: verify `proof_count * 32 ≤ remaining_bytes` and `inner_proof_count ≤ proof_count`.
- Before reading `tbs[tbs_len]`: verify `tbs_len ≤ remaining_bytes` and `tbs_len ≥ 1`.
- Before reading `issuer_sig[issuer_sig_len]` (Mode 0): verify `issuer_sig_len ≤ remaining_bytes`.
- Before reading `cosigs[witness_count]` (Mode 0): verify `witness_count * 76 ≤ remaining_bytes`.

Parsers MUST reject payloads where any declared length would read past the end
of the buffer.

### Bound Mode vs. Self-Describing Mode

The `self_describing` flag controls whether the payload envelope carries the
full origin string. It has no effect on the log entry CBOR or the entry hash
construction — both are identical in both modes.

**The entry hash is always:**

```
entry_hash = SHA-256(0x00 || tbs)
```

where `tbs` is `entry_type_byte || CBOR(AssertionLogEntry)`. The CBOR entry
contains no origin field in either mode. The hash construction is invariant —
the `self_describing` flag affects only the envelope, never the authenticated
content.

**Bound mode (flag bit 7 = 0).** The payload carries only `origin_id`. The
verifier uses this to look up the full origin from its trust configuration.

**Self-describing mode (flag bit 7 = 1).** The payload carries `origin_id`
plus the full UTF-8 origin string. The verifier reads the origin string from
the envelope, looks it up in its trust configuration using `origin_id` as a
routing shortcut, and MUST verify the origin string from the envelope matches
the origin string in the trust configuration entry located by `origin_id`. This
check MUST occur even when the checkpoint is served from cache.

In both modes the verifier MUST confirm the origin string matches the origin in
the cosigned checkpoint before proceeding to inclusion proof verification.

---

## Log Entry Format

Log entries are CBOR-encoded. There are two entry types, distinguished by a
leading type byte.

```
0x00  null_entry       reserved; issuers MUST log a null_entry at index 0 of every log
0x01  data_assertion   bearer token — no key, no possession proof
0x02  key_assertion    key-bound — possession proof required at verification
```

Verifiers MUST reject entries with unrecognized type bytes.

### Type 0x00: null_entry

The null_entry is a reserved placeholder. Its wire format is the type byte
alone — no CBOR payload follows:

```
tbs = 0x00
entry_hash = SHA-256(0x00 || 0x00)
```

The entry carries no claims, no schema_id, no timestamps. It exists solely
to occupy index 0 of every log, establishing that index 0 is never a valid
data or key assertion. Verifiers MUST reject any payload whose `entry_index`
is 0. This check MUST occur immediately after decoding the payload header,
before consulting the trust configuration, cache, or inclusion proof. A payload
with `entry_index` 0 is structurally invalid — `null_entry` carries no claims
and cannot be a valid assertion regardless of whether its inclusion proof is
well-formed. Issuers MUST produce a `null_entry` as the first logged entry
when initializing a new log.

### Type 0x01: Data Assertion

A bearer assertion. The QR code is the entitlement. Whoever holds it presents
it. No cryptographic relationship between the bearer and the assertion is
assumed or required.

```
DataAssertionLogEntry = {
    2: [uint, uint],  ;; [issuance_time, expiry_time] Unix timestamps
    3: uint,          ;; schema_id
    4: any,           ;; claims (schema-dependent)
}
```

The origin is never embedded in the CBOR entry. It lives in the payload
envelope and is authenticated by the checkpoint signature, not by the entry
content. Field numbering starts at 2. **Field 1 is permanently reserved and
MUST NOT be used.** Its absence is load-bearing: the hash construction depends
on the CBOR being identical in both bound and self-describing modes, and adding
an optional field 1 in a future extension would silently break hash
compatibility with existing deployments. Any extension requiring per-entry
issuer identity MUST define a new entry type rather than repurposing field 1.

Examples: event tickets, package labels, inspection certificates, permits,
prescriptions.

**Single-use enforcement.** Type 0x01 assertions are bearer tokens: MTA-QR does
not prevent the same assertion from being presented simultaneously on multiple
devices. Deployments where single-use semantics are required MUST implement
application-layer deduplication at the verifier.

### Type 0x02: Key Assertion

A key-bound assertion. The assertion is only usable by the entity that can
prove possession of a specific private key. After the inclusion proof verifies,
the verifier issues a challenge (a fresh nonce) and requires the bearer to
produce a valid signature over it using the key whose hash is in the log entry.

```
KeyAssertionLogEntry = {
    2: [uint, uint],  ;; [issuance_time, expiry_time] Unix timestamps
    3: uint,          ;; schema_id
    4: bstr,          ;; SHA-256 of subject public key bytes
    5: int,           ;; COSE algorithm identifier for the subject key
    6: uint,          ;; attestation_format (see registry below)
    7: bstr,          ;; attestation_binding
    8: any,           ;; claims (schema-dependent)
}
```

**Field 1 is permanently reserved** for the same reason as DataAssertionLogEntry.
Fields 6 and 7 are optional.

**Subject public key encoding.** Field 4 is the SHA-256 of the raw public key
bytes — not SubjectPublicKeyInfo, not COSE_Key. The COSE algorithm identifier
in field 5 determines which specification defines the byte format. The key
itself is not logged — only its hash. The verifier receives the actual public
key bytes from the bearer during the challenge-response, hashes them, and checks
the result against field 4.

#### Attestation Format Registry

| Value | Scheme |
|-------|--------|
| 0 | none |
| 1 | FIDO / WebAuthn authenticator attestation |
| 2 | TPM 2.0 (TPM2_Certify / TPM quote) |
| 3 | DICE / RIoT firmware attestation |
| 4 | RATS Attestation Result (RFC 9334 EAT) |
| 5 | AWS Nitro Enclaves |
| 6 | Intel TDX |
| 7 | ARM CCA |
| 8 | AMD SEV-SNP |
| 255 | Schema-defined (see claims field) |

Field 7 carries either an evidence hash (SHA-256 of the raw attestation object,
with full evidence available off-log by entry index) or an attestation result
hash (SHA-256 of a RATS Verifier's signed Attestation Result). In both options
the actual attestation material lives off the log.

The challenge-response protocol is out of scope for this format specification
and is defined by the schema_id. **Type 0x02 is design-complete and
deployment-incomplete** pending a separate challenge-response protocol spec. No
two independent Type 0x02 implementations will be interoperable without it.

### Entry Hash Construction

Both entry types are hashed identically, per RFC 6962 §2.1 leaf convention:

```
entry_hash = SHA-256(0x00 || tbs)
```

where `tbs` is `entry_type_byte || CBOR(AssertionLogEntry)`. The construction is
invariant across bound and self-describing modes — the CBOR entry carries no
origin field in either case.

**CBOR determinism.** All log entries MUST be encoded in Deterministic CBOR per
RFC 8949 §4.2 (integer keys, definite-length encoding, map keys in bytewise
lexicographic order). Verifiers MUST reject entries that are not in canonical
form.

Non-canonical CBOR produces a Merkle inclusion proof failure (root mismatch),
not a CBOR decoding error. The verifier recomputes `entry_hash = SHA-256(0x00 ‖ tbs)`
over the bytes in the payload; if the issuer used non-canonical encoding, the
recomputed hash differs from what the issuer logged and the proof path to the
checkpoint root does not exist. There is no CBOR-layer error at the verifier.
Diagnosing this requires running the raw `tbs` bytes through a canonical
re-encoder and comparing — not something verifiers do in production. Issuers
MUST validate canonical encoding before issuance.

**CBOR library guidance.** Most popular CBOR libraries do not produce RFC 8949
§4.2 deterministic encoding by default. Common library-specific settings:
- `cbor2` (Python): `canonical=True`
- `tinycbor`: `CborEncodeFlags` canonical mode flag
- `fxamacker/cbor` (Go): `CanonicalEncOptions()` or `EncOptions{Sort: cbor.SortBytewiseLexical}`
- TypeScript/JavaScript: `cborg` produces canonical encoding by default. `cbor-x`
  does NOT produce RFC 8949 §4.2 deterministic encoding for `Map` inputs with
  integer keys regardless of its `canonical` option; use `cborg` for encoding.
  When decoding with `cborg`, pass `{ useMaps: true }` — without it, `cborg.decode()`
  returns a plain JS object for CBOR maps with integer keys, and `.get(2)` on a
  plain object returns `undefined` silently.

Issuers SHOULD include a round-trip canonicalization test in their issuance
pipeline: encode the entry, decode it, re-encode with a reference deterministic
encoder, and verify the byte sequences are identical before deploying.

**Inclusion proof computation.** The Merkle path from `entry_hash` to root is
computed per RFC 6962 §2.1.3. Sibling hashes in the proof array are ordered
from leaf to root. At each level: `SHA-256(0x01 || left || right)` where the
current node is placed left or right based on whether `entry_index` at that
level is even (left child) or odd (right child) respectively.

---

## Tiled Two-Level Merkle Tree

MTA-QR uses a two-level tiled Merkle tree rather than a flat RFC 6962 tree.
The reason is payload size stability under high issuance volume.

A flat RFC 6962 tree over N entries produces inclusion proofs of ⌈log₂(N)⌉
hashes. Every time the log doubles in size, the proof grows by one 32-byte
hash. For a high-volume issuer — say a transit system rotating membership
cards every 5 minutes — a flat tree produces larger QR codes over time until
the payload no longer fits a fixed QR version. The tiled structure eliminates
this growth by bounding proof size to a fixed maximum regardless of total
log size.

**Structure.** Entries are organized into fixed-size batches of `BATCH_SIZE`
entries. Each batch has its own inner Merkle tree whose root is a `batch_root`.
The `batch_root` values are then organized into an outer (parent) Merkle tree
whose root is the checkpoint root hash.

**Two-phase inclusion proof.** Each QR payload carries two concatenated proof
segments, split by `inner_proof_count`:

- **Phase A (inner):** `inner_proof_count` sibling hashes from `entry_hash` to
  `batch_root` (the batch-level proof).
- **Phase B (outer):** the remaining `proof_count − inner_proof_count` hashes
  from `batch_root` to the parent root (the checkpoint root hash).

**Size bound.** With `BATCH_SIZE=16` and `OUTER_MAX_BATCHES=16`:

- Inner proof: ≤ log₂(16) = 4 hashes (128 bytes), fixed forever regardless of
  how many batches exist.
- Outer proof: ≤ log₂(16) = 4 hashes (128 bytes), fixed until 256 total entries
  are reached, at which point the outer tree rolls over to a new log epoch.
- Maximum total proof: 8 hashes = 256 bytes, regardless of total log size.

This is why Mode 1 payloads have a stable size. A ticket issued on day one and
a ticket issued after a year of high-volume issuance produce payloads of the
same size, encoding to the same QR version.

**`BATCH_SIZE` and the trust configuration.** `BATCH_SIZE` is a deployment
parameter that must be consistent between issuers and verifiers. It is carried
in the trust configuration so verifiers know how to interpret the
`inner_proof_count` split. The reference implementation uses `BATCH_SIZE=16`.

**Roll-over.** When the outer tree fills (num_batches exceeds
`OUTER_MAX_BATCHES`), the issuer resets the log and issues a new null_entry at
index 0 of the new epoch. Existing payloads from the previous epoch remain
verifiable because they carry their own proof hashes — they do not depend on
the current log state.

---

## Trust Configuration Schema

The trust configuration is the out-of-band data a verifier must have before it
can verify any payload from an issuer. It is a JSON object with the following
fields:

```json
{
  "origin":          "example.com/access/ed25519/v1",
  "issuer_pub_key_hex": "...",
  "sig_alg":         6,
  "issuer_key_name": "example-issuer+abcd1234+<base64_pubkey>",
  "witnesses": [
    {
      "key_name": "witness-a+11223344+<base64_pubkey>"
    }
  ],
  "witness_quorum":  1,
  "checkpoint_url":  "https://example.com/checkpoint",
  "revocation_url": "https://example.com/revoked",
  "batch_size":      16
}
```

| Field | Type | Description |
|-------|------|-------------|
| `origin` | string | Full UTF-8 origin string. Must be unique per (key, algorithm) pair. |
| `issuer_pub_key_hex` | hex string | Issuer public key bytes, hex-encoded. Format depends on `sig_alg`. |
| `sig_alg` | integer | Algorithm identifier matching the payload flags bit field. |
| `issuer_key_name` | string | Note verifier key name for the issuer key, used to locate the issuer's signature line in checkpoint notes. |
| `witnesses` | array | List of witness entries. Each has a `key_name` in signed-note verifier format. |
| `witness_quorum` | integer | Minimum number of distinct witness cosignatures required. Must be ≥ 1 and ≤ len(witnesses). |
| `checkpoint_url` | string | URL of the `GET /checkpoint` endpoint. Used by Mode 1 verifiers on cache miss. |
| `batch_size` | integer | Batch size for the two-phase Merkle proof. Default 16. Must match the issuer's configuration. |
| `revocation_url` | string | URL of the `GET /revoked` endpoint. Used by verifiers to fetch the revocation artifact on cache miss or first load. Derived from the issuer base URL as `<base_url>/revoked`. |

The trust configuration is distributed out-of-band by the issuer — typically
bundled with the verifier application or fetched once at provisioning time from
a well-known endpoint. It is not communicated via the QR payload.

---

## Verification Modes

### Mode 0: Embedded (No Checkpoint Fetch)

The QR payload includes the assertion content, inclusion proof, and a compact
cosigned checkpoint — root hash, issuer signature, and witness cosignatures.
No network access is required at verification time, and no separate
checkpoint endpoint needs to be reachable.

**A trust configuration is still required.** The embedded signatures cannot
be verified without the issuer's public key and witness public keys. These
must be distributed out-of-band as a trust configuration before scanning.
Mode 0 eliminates the checkpoint fetch, not the trust distribution step.

**Mode 0 signed content.** The `issuer_sig` field is a note signature over the
checkpoint body, reconstructed from the payload fields as:

```
<origin> + "\n" + decimal(tree_size) + "\n" + base64(root_hash) + "\n"
```

Each `WitnessCosig` is verified against the cosignature/v1 message using the
same reconstructed body. The `cosig.timestamp` field provides the timestamp for
the cosignature message; it MUST equal the big-endian uint64 in the `WitnessCosig`
binary representation.

The `root_hash` field serves two roles: it is base64-encoded into the
reconstructed checkpoint body (over which `issuer_sig` is verified), and it is
the expected Merkle root against which the inclusion proof is verified. Verifiers
MUST use the same `root_hash` bytes for both operations.

**Raw byte budget (ECDSA P-256, 10-hash proof, minimal assertion):**

| Component | Bytes |
|-----------|-------|
| Fixed header overhead | 64 |
| Inclusion proof (10 × 32) | 320 |
| Assertion TBS | ~100 |
| Issuer ECDSA P-256 signature | 64 |
| 2× witness cosignature (76 bytes each) | 152 |
| **Total** | **~700** |

**Raw byte budget (FN-DSA-512, 10-hash proof, minimal assertion):**

| Component | Bytes |
|-----------|-------|
| Fixed header overhead | 64 |
| Inclusion proof (10 × 32) | 320 |
| Assertion TBS | ~100 |
| Issuer FN-DSA-512 signature | up to 666 |
| 2× witness cosignature (76 bytes each) | 152 |
| **Total** | **~1,302** |

**Best for:** Deployments where the issuer's checkpoint endpoint may be
unreachable at scan time, or where payloads must be independently verifiable
without a live backend service. Classical issuers (ECDSA P-256, Ed25519)
keep the payload size manageable. PQC Mode 0 with FN-DSA-512 adds up to 666
bytes for the issuer signature and requires controlled print and scan conditions.

### Mode 1: Cached Checkpoint (Offline After Prefetch)

The QR payload includes the assertion content and inclusion proof. No signatures
are embedded. The verifier resolves the checkpoint from its local cache.

On cache miss, the verifier fetches the cosigned checkpoint, verifies the issuer
signature (using the algorithm identified by `sig_alg` in the trust
configuration — never inferred from signature length) and witness cosignature
quorum, then caches the result. The cache key MUST be `(full_origin, tree_size)`
where `full_origin` is the complete origin string from the trust configuration,
not `origin_id`.

**Size estimate (any issuer algorithm, 12-hash proof, minimal assertion):**

| Component | Bytes |
|-----------|-------|
| Fixed header overhead | 29 |
| Inclusion proof (12 × 32) | 384 |
| Assertion TBS | ~100–150 |
| **Total** | **~513–563** |

**Best for:** The general case — tickets, prescriptions, permits, badges,
packages. Any issuer whose verifiers have a charge cycle.

### Mode 2: Online Reference

The QR payload contains only the assertion content and log coordinates.
The verifier fetches the inclusion proof from a tile server and the checkpoint
from the issuer's endpoint at scan time.

The security properties of a correctly verified Mode 2 payload are identical
to Mode 1. The inclusion proof is cryptographically verifiable regardless of
how it was delivered: any proof must lead to a root the witnesses have cosigned,
and producing a valid proof for an entry that was never logged would require
breaking SHA-256. The verifier checks the math either way.

The practical difference from Mode 1 is operational: Mode 1 works offline
after a prefetch; Mode 2 requires network access at scan time to fetch the
checkpoint and inclusion proof. Mode 2 deployments MUST serve both endpoints
over TLS with verifiable server identity.

**Best for:** High-throughput fixed-infrastructure scanning where connectivity
is guaranteed and the smallest possible payload size is a priority.

---

## Issuance Flow

Steps 1–4 are common to all modes. Step 5 varies by mode.

1. The asserting party requests issuance.
2. The issuer validates the request.
3. The issuer appends the log entry to the issuance log.
4. Periodically (every 2–30 seconds depending on throughput): compute the new
   Merkle root, format a checkpoint body, sign with the issuer key per `sig_alg`,
   submit to the witness network, collect cosignatures, publish at `GET /checkpoint`.
5. For each log entry in this batch, assemble the `MTAQRPayload` based on mode:

   **Mode 0:** Compute the two-phase inclusion proof. Embed the proof, plus the
   checkpoint root hash, issuer signature, and witness cosignatures directly in
   the payload. The payload is self-contained for verification purposes.

   **Mode 1:** Compute the two-phase inclusion proof. Embed the proof in the
   payload. Leave out the checkpoint signatures — verifiers fetch those
   separately and cache them.

   **Mode 2:** Set `proof_count=0`. Embed only the log coordinates
   (`tree_size`, `entry_index`). The verifier fetches the proof at scan time.

6. Encode the payload to binary and generate the QR code.

---

## Verification Flow (Mode 1)

Both entry types share the same checkpoint and inclusion proof verification
path. They diverge only after the inclusion proof succeeds. Claims MUST NOT be
decoded or acted on until all verification steps below have passed.

```
1.  Decode MTAQRPayload binary.

2.  Reject entry_index == 0 immediately. No further processing required.

3.  If self_describing=1: read origin from envelope. Look up trust anchor by
    origin_id. MUST verify envelope origin == trust config origin. If
    self_describing=0: look up trust anchor by origin_id.

4.  Verify sig_alg in payload == sig_alg in trust config for this origin.
    Reject on mismatch (downgrade attack prevention).

5.  Look up (full_origin, tree_size) in local checkpoint cache.

6.  On cache MISS:
    a. Fetch GET /checkpoint.
    b. Verify response tree_size >= payload tree_size.
    c. Verify issuer signature over checkpoint body using the algorithm from
       the trust config (never inferred from signature byte length).
    d. Verify >= N distinct witness cosignatures from trusted witness keys.
       Ignore cosignatures from witnesses not in the trust config before
       counting. Reject duplicate key_ids. Quorum count MUST be over distinct
       trusted keys only.
    e. Cache (full_origin, tree_size) -> root_hash.

7.  Compute entry_hash = SHA-256(0x00 || tbs).

8.  Verify tiled two-phase Merkle inclusion proof (RFC 6962 §2.1.3).

    The checkpoint root_hash is the PARENT tree root (Merkle root over batch
    roots), not a flat root over all entry hashes. Verification proceeds in
    two phases using the inner_proof_count split from the payload:

    Phase A — Inner proof (entry → batch root):
      - batch_index = entry_index / BATCH_SIZE
      - inner_index = entry_index % BATCH_SIZE
      - batch_size  = min(BATCH_SIZE, tree_size - batch_index * BATCH_SIZE)
      - Walk the first inner_proof_count sibling hashes from entry_hash to
        compute batch_root. Reject if Phase A fails.

    Phase B — Outer proof (batch root → parent root):
      - num_batches = ceil(tree_size / BATCH_SIZE)
      - Walk the remaining proof_count − inner_proof_count hashes from
        batch_root. The result MUST equal root_hash. Reject on mismatch.

    BATCH_SIZE is a deployment parameter carried in the trust configuration.
    The reference implementation uses BATCH_SIZE = 16.

9.  Check entry_index not revoked.
    Fetch the revocation artifact from revocation_url on cache miss.
    Query the cached cascade: if Query(cascade, entry_index) = REVOKED, reject.
    Apply fail-closed or fail-open policy if no artifact is available.
    See §Revocation for the full verifier algorithm.

10. Check expiry: expiry_time MUST be > (current_time - grace_period).
    Default grace period: 10 minutes (600 seconds).

11. Decode entry_type_byte (first byte of tbs):
    - 0x01 data_assertion: decode and act on claims.
    - 0x02 key_assertion: proceed to possession proof.
    - Any other value: reject.

12. (Key assertions only)
    a. Parse subject_public_key_hash and key_algorithm from CBOR.
    b. Issue challenge nonce via secondary channel.
    c. Receive claimed public key bytes and nonce signature.
    d. FIRST verify SHA-256(claimed_key_bytes) == subject_public_key_hash.
    e. THEN verify nonce signature using claimed key bytes per COSE algorithm.
```

**Normative requirements:**

The cache key MUST be `(full_origin, tree_size)` where `full_origin` is the
complete origin string from the trust configuration, not `origin_id`. Two
legitimate logs from the same issuer that share an origin string but differ in
signing key or algorithm will have different Merkle roots for the same
`tree_size`. Keying by `origin_id` causes the verifier to serve the wrong root
without any error signal. The failure presents as a Merkle root mismatch, which
is extremely difficult to diagnose without knowing the cache key is wrong.

The witness quorum count MUST be over distinct witness public keys from the
verifier's trust configuration. Cosignatures from witnesses not in the trust
configuration MUST be ignored before the quorum count. Duplicate `key_id`s
in a single payload MUST be rejected before the quorum check.

For key assertions, `SHA-256(claimed_key_bytes)` MUST be verified against
`subject_public_key_hash` before the nonce signature is verified.

Expiry grace period: verifiers SHOULD apply 10 minutes (600 seconds) to account
for unsynchronized clocks in offline deployments. Verifiers MUST NOT apply a
grace period greater than 10 minutes. Issuers SHOULD NOT issue assertions with
validity windows shorter than twice the configured grace period.

---

## Verification Flow (Mode 0)

Mode 0 verification follows the same structure as Mode 1 but replaces the
checkpoint fetch step with verification of the embedded checkpoint fields.

**Prerequisites.** A trust configuration for the origin must be pre-loaded.
The embedded signatures are verified using the issuer public key and witness
public keys from that trust configuration. Mode 0 does not eliminate the
trust distribution requirement — it only eliminates the checkpoint fetch.

```
1.  Decode MTAQRPayload binary.

2.  Reject entry_index == 0 immediately.

3.  If self_describing=1: read origin from envelope. Look up trust anchor by
    origin_id. MUST verify envelope origin == trust config origin. If
    self_describing=0: look up trust anchor by origin_id.

4.  Verify sig_alg in payload == sig_alg in trust config for this origin.
    Reject on mismatch (downgrade attack prevention).

5.  Reconstruct the checkpoint body from the embedded fields:

      <origin> + "\n" + decimal(tree_size) + "\n" + base64(root_hash) + "\n"

    where <origin> is the full origin string from the trust configuration
    (not the origin_id, and not a truncated form).

6.  Verify issuer_sig over the reconstructed checkpoint body using the
    algorithm identified by sig_alg in the trust configuration — never
    inferred from signature byte length. Reject on failure.

7.  Verify >= N distinct WitnessCosig entries using witness public keys from
    the trust configuration, where N is witness_quorum. Each cosignature is
    verified against the cosignature/v1 message format using the reconstructed
    checkpoint body and the cosig.timestamp field. Ignore cosignatures from
    key_ids not present in the trust configuration. Reject duplicate key_ids.
    Quorum count MUST be over distinct trusted keys only.

8.  Compute entry_hash = SHA-256(0x00 || tbs).

9.  Verify tiled two-phase Merkle inclusion proof against root_hash using the
    same algorithm as Mode 1 steps 8a–8b. The root_hash from the payload is
    the expected value; it has already been authenticated in steps 6–7.

10. Check entry_index not revoked. Same procedure as Mode 1 step 9.

11. Check expiry: expiry_time MUST be > (current_time - grace_period).

12. Decode entry_type_byte and proceed as in Mode 1 steps 11–12.
```

**Key difference from Mode 1:** Steps 5–7 replace the checkpoint cache lookup
and conditional fetch (Mode 1 steps 5–6e). In Mode 0 the checkpoint
authenticity is established by verifying the embedded signatures directly
against the trust configuration rather than by fetching a signed note from
a network endpoint.

---

## Verification Flow (Mode 2)

Mode 2 payloads carry no inclusion proof (`proof_count=0`). The verifier must
fetch both the checkpoint and the inclusion proof from the issuer's tile server
at scan time.

**This SDK does not implement tile fetching.** The steps below describe the
complete Mode 2 verification algorithm for implementors building a production
Mode 2 scanner. The reference SDK validates everything up to step 6 and then
returns a result with `mode=2` without completing steps 7–8. Callers must
check the `mode` field on the result and gate on it — a Mode 2 result from
this SDK has not verified inclusion, because the tile fetch is not implemented,
not because inclusion proof verification is inherently weaker in Mode 2.

```
1.  Decode MTAQRPayload binary. Confirm proof_count == 0.

2.  Reject entry_index == 0 immediately.

3.  If self_describing=1: read origin from envelope. Look up trust anchor by
    origin_id. MUST verify envelope origin == trust config origin. If
    self_describing=0: look up trust anchor by origin_id.

4.  Verify sig_alg in payload == sig_alg in trust config for this origin.
    Reject on mismatch (downgrade attack prevention).

5.  Fetch GET /checkpoint from the trust config checkpoint_url.
    Verify response tree_size >= entry_index + 1 (entry must be in this tree).
    Verify issuer signature and witness cosignature quorum exactly as in
    Mode 1 steps 6c–6d.

6.  Compute entry_hash = SHA-256(0x00 || tbs).

7.  Fetch the inclusion proof from the tile server. The tile addressing scheme
    is not yet defined — see Open Questions (SPEC.md does not define the Mode 2
    tile server API). Verify the two-phase tiled Merkle inclusion proof against
    the checkpoint root hash from step 5.

8.  Check entry_index not revoked (§Revocation). Check expiry.

9.  Decode entry_type_byte and act on claims.
```

**Security note.** Steps 5–7 require network access at scan time. The
checkpoint (step 5) is verified against the trust configuration exactly as in
Mode 1 — the issuer signature and witness cosignatures are checked
cryptographically and cannot be fabricated. The inclusion proof (step 7) is
also cryptographically verifiable: a valid proof must lead to the witnessed
root hash, and constructing a false proof for an entry that was never logged
would require breaking SHA-256. The security properties of a correctly
completed Mode 2 verification are therefore identical to Mode 1. Mode 2
deployments MUST serve both the checkpoint and tile endpoints over TLS with
verifiable server identity to prevent MITM substitution of either.

---

## Revocation

### Design

Revocation in MTA-QR follows the same architectural pattern as CRLite
(Larisch et al., IEEE S&P 2017; Schanck, IEEE S&P 2025): the issuer constructs
a compact probabilistic membership test encoding the revoked set, signs it with
the same key used to sign checkpoints, and distributes it to verifiers on the
same charge-cycle schedule as checkpoint updates. Verifiers query the locally
cached artifact at scan time — no network access required.

This architecture maps directly onto MTA-QR because the issuer is also the
aggregator. In the WebPKI, CRLite requires a trusted third party to aggregate
revocation information from many CAs. In MTA-QR, each issuer operates their
own log and controls their own revocation set. The issuer constructs the filter
cascade directly — no aggregation step is needed, and the signing key is already
distributed to verifiers via the trust configuration.

### The Two-Set Construction

The filter cascade encodes two disjoint sets derived from the log:

- **R (revoked):** the set of `entry_index` values the issuer has explicitly revoked.
- **S (valid, non-revoked):** the set of `entry_index` values that have been
  issued, have not expired at artifact generation time, and are not in R.

The universe is indices 1 through `tree_size - 1`. Index 0 (null entry) is
always excluded from both sets.

A Bloom filter cascade over (R, S) produces a structure with zero false negatives
and a configurable false positive rate. The false positive direction is deliberately
conservative: a false positive causes the verifier to incorrectly reject a valid
assertion, but never to incorrectly accept a revoked one.

### Normative Construction Parameters

These parameters MUST be used exactly as specified. Any deviation produces
cascade bytes that will not match test vectors and will not interoperate.

**Element encoding.** Each `entry_index` is encoded as an 8-byte big-endian
unsigned integer for hashing. No other encoding is permitted.

**Hash function.** SHA-256. Given an element `x` (8-byte big-endian uint64) and
hash function index `i` (0-indexed), the j-th bit position in a filter of `m` bits is:

```
bit_position(x, i) = (big_endian_uint64(SHA-256(x || uint8(i))[0:8])) mod m
```

where `x || uint8(i)` is the 8-byte element followed by one byte containing `i`.

**Number of hash functions per level.** `k = 1`. A single hash function per level.
This is valid for the cascade construction because false positives are eliminated
at subsequent levels rather than by multiple hash functions within a single level.

**Bit array size per level.** For a level encoding `n` elements:

```
m = max(ceil(n * BITS_PER_ELEMENT), MIN_FILTER_BITS)

BITS_PER_ELEMENT = 1.44   (≈ ln(2)^-2, optimal for 50% FPR)
MIN_FILTER_BITS  = 64
```

Round `m` up to the nearest multiple of 8 so the bit array is byte-aligned.
`ceil(n * 1.44)` with a minimum of 64 bits.

**Cascade construction algorithm:**

```
function BuildCascade(R, S):
  levels = []
  current_fp_set = S  // start: false positives at Level 0 are entries in S
  include_set = R     // Level 0 encodes R
  level_index = 0

  while include_set is not empty:
    m = max(ceil(len(include_set) * 1.44), 64)
    m = ceil(m / 8) * 8  // round up to byte boundary
    bits = zero_array(m)

    for x in sorted(include_set, ascending):
      bit = bit_position(x, level_index) mod m
      bits[bit] = 1

    levels.append({bit_count: m, bits: bits})

    // Compute false positives: elements in current_fp_set that hash into bits
    new_fp_set = {}
    for x in current_fp_set:
      bit = bit_position(x, level_index) mod m
      if bits[bit] == 1:
        new_fp_set.add(x)

    // Next level: encode the false positives to eliminate them
    include_set = new_fp_set
    current_fp_set = new_fp_set
    level_index += 1

  return levels
```

**Insertion order.** Elements MUST be inserted in ascending `entry_index` order.
The bit array state after insertion must be deterministic given fixed inputs; any
other ordering is non-normative.

**Query algorithm:**

```
function Query(cascade, x):
  for i, level in enumerate(cascade.levels):
    bit = bit_position(x, i) mod level.bit_count
    in_filter = level.bits[bit] == 1
    if i == 0:
      if not in_filter: return NOT_REVOKED   // definitely not in R
      result = REVOKED                        // tentatively in R
    else:
      if in_filter:
        result = NOT_REVOKED                  // this level's filter caught it: was FP
      else:
        return result                         // not caught: confirmed
  return result
```

More precisely: the query result alternates interpretation at each level. Level 0
"in filter" means "potentially revoked." Level 1 "in filter" means "Level 0 was
a false positive — not revoked." Level 2 "in filter" means "Level 1 was a false
positive — revoked again." And so on. If the element falls out of the cascade at
any level (the bit is 0), the current interpretation at that level is the final
answer. If all levels are traversed, the interpretation at the last level is the
final answer.

### Binary Encoding

The cascade is serialized as follows. All integer fields are big-endian.

```
uint8   num_levels          (number of levels, 0..255)
for each level (index 0..num_levels-1):
  uint32  bit_count         (number of bits in this level's filter)
  uint8   k                 (number of hash functions; always 1 in this spec)
  ceil(bit_count/8) bytes   bit_array (MSB of first byte = bit 0)
```

Bit indexing: bit `i` of the filter is stored in byte `i/8` at bit position
`7 - (i mod 8)` (MSB-first within each byte). Bit 0 is the most significant
bit of byte 0.

The total size of the serialized cascade is:
`1 + num_levels * (4 + 1) + sum(ceil(bit_count_i / 8) for each level i)`

An empty cascade (R is empty at construction time) is encoded as `num_levels = 0`
(1 byte). Querying an empty cascade MUST return NOT_REVOKED for all inputs.

### Wire Format

The revocation artifact is a signed note with the same four-line body structure
as a checkpoint. The body is what the issuer signature covers.

**Body:**
```
<origin>\n
<tree_size decimal>\n
crlite-v1\n
<base64(cascade_bytes)>\n
```

The `crlite-v1` literal is the artifact type identifier. Verifiers MUST reject
artifacts with unrecognized type identifiers. `cascade_bytes` is the binary
encoding defined above, base64-encoded per RFC 4648 §4 (standard alphabet,
`=` padding, no line breaks).

**Full signed note:**
```
<origin>
<tree_size decimal>
crlite-v1
<base64(cascade_bytes)>

— <issuer_key_name> <base64(4_byte_key_hash || issuer_signature)>
```

The issuer signature is computed over the four-line body (same as a checkpoint
body) using the same key and algorithm identified in the trust configuration.
The `issuer_key_name` and key hash derivation follow the c2sp.org/signed-note
convention, identical to how the checkpoint issuer signature is computed.

Verifiers MUST verify this signature before trusting the artifact. An artifact
with an invalid or missing signature MUST be discarded entirely.

### Trust Configuration

The trust configuration MUST include a `revocation_url` field alongside
`checkpoint_url`. Verifiers use this URL to fetch the revocation artifact.

```json
{
  "revocation_url": "https://example.com/revoked"
}
```

By convention, `revocation_url` is `<base_url>/revoked` where `<base_url>` is
the same base as `checkpoint_url`. Issuers that do not support revocation SHOULD
omit this field. Verifiers that receive a trust config without `revocation_url`
MUST behave as if no revocation artifact is available and apply the fail-open
or fail-closed policy per their deployment configuration.

### Distribution

The artifact is served at `GET /revoked` (derived from `revocation_url` in the
trust config). Verifiers fetch it on the same charge-cycle schedule as checkpoint
updates. The endpoint returns the full signed note as `text/plain; charset=utf-8`.

**Full artifact (`GET /revoked`):** A complete cascade covering all issued
non-expired entries. This is the only format defined for v1.

**Delta updates** are deferred to v2. The `crlite-v1-delta` artifact type
identifier is reserved but its format is not defined in this version. Issuers
that need bandwidth-efficient updates in high-volume deployments SHOULD track
the Clubcard construction (Schanck 2025) for future reference.

### Verifier Behavior

**Cache key.** The revocation cache is keyed on `full_origin` only (not
`full_origin + tree_size`). Unlike the checkpoint cache — which caches by
`tree_size` because old roots remain valid for old payloads — the revocation
artifact is always superseded by newer versions. Verifiers keep the most recent
artifact for each origin and refresh it when the issuer publishes a new checkpoint.

**Coverage check.** If the cached artifact's `tree_size <= entry_index`, the
entry is not covered (it was issued after the artifact was generated). Verifiers
MUST NOT silently pass uncovered entries. The RECOMMENDED behavior is to fetch
a fresh artifact from `revocation_url` on cache miss, exactly as the checkpoint
is fetched on cache miss.

**Fail-closed posture (RECOMMENDED).** If no artifact is available (not cached
and fetch failed or network unavailable), the verifier declines to verify and
reports the revocation check as failed. A missing artifact cannot be
distinguished from an attacker serving an empty revocation list.

**Fail-open posture (non-default).** Verifiers in deployments where revocation
is best-effort MAY configure fail-open: if no artifact is available, the
revocation check passes with a warning in the verification trace. This MUST be
an explicit deployment configuration. The verification trace MUST clearly
indicate that the revocation check was skipped.

**Query.** Given a cached artifact covering `entry_index`:
1. Decode the base64 cascade bytes.
2. Verify the issuer signature over the four-line body.
3. Call `Query(cascade, entry_index)`.
4. If `REVOKED`, reject the payload.
5. If `NOT_REVOKED`, proceed.

Step 2 MUST be performed on every use of a cached artifact, not only at load
time, to prevent tampering with a cached artifact in memory.

### Size Estimates

These are computed from the normative construction parameters above.

For `n` revoked entries at `BITS_PER_ELEMENT = 1.44`, the Level 0 filter is
approximately `1.44 × n` bits. Subsequent levels are much smaller (encoding
only the false positive set, which shrinks rapidly). Total cascade size is
approximately `1.44 × n / 8` bytes plus a small constant per level.

| Revoked entries | Approximate full cascade |
|----------------|--------------------------|
| 10 | ~64 bytes (minimum filter size dominates) |
| 100 | ~200 bytes |
| 1,000 | ~1.8 KB |
| 10,000 | ~18 KB |
| 100,000 | ~180 KB |

### References

- Larisch, Choffnes, Levin, Maggs, Mislove, Wilson. "CRLite: A Scalable System
  for Pushing All TLS Revocations to All Browsers." IEEE S&P 2017, pp. 539–556.
  https://ieeexplore.ieee.org/document/7958597
- Schanck. "Clubcards for the WebPKI: smaller certificate revocation tests in
  theory and practice." IEEE S&P 2025.
  https://research.mozilla.org/files/2025/04/clubcards_for_the_webpki.pdf
- Mozilla CRLite reference implementation (MPL-2.0):
  https://github.com/mozilla/crlite
- Mozilla rust-cascade library (MPL-2.0):
  https://github.com/mozilla/rust-cascade

---

## Size Summary

| Mode | Issuer algorithm | Approx. raw payload | QR version (M ECC) | Notes |
|------|-----------------|--------------------|--------------------|-------|
| 0 Embedded | ECDSA P-256 | ~700 bytes | Version 18–20 | Recommended classical start |
| 0 Embedded | Ed25519 | ~700 bytes | Version 18–20 | Recommended classical start |
| 0 Embedded | FN-DSA-512 | ~1,302 bytes | Version 40 (marginal) | PQC; controlled conditions only |
| 0 Embedded | ML-DSA-44 | ~3,000 bytes | Not feasible | — |
| 1 Cached | Any | ~513–563 bytes | Version 15–20 | General recommendation |
| 2 Online | Any | ~30 bytes | Version 3–4 | Fixed infrastructure only |

---

## Test Vectors

These vectors use zero bytes and short ASCII strings. Every implementation
should reproduce these values exactly before handling real data.

### Vector 1: Checkpoint Body

```
origin:         "example.com/mta-qr/v1"
tree_size:      3
root_hash:      0000...0000 (32 zero bytes)
root_hash_b64:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

Checkpoint body hex:
```
6578616d706c652e636f6d2f6d74612d71722f76310a330a414141414141414141414141414141414141414141414141414141414141414141414141414141414141413d0a
```

Decoded as ASCII: `example.com/mta-qr/v1\n3\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n`

Three lines, each terminated by `\n`, including the final line. Total: 69 bytes.
The `=` padding in the base64 root hash is mandatory.

### Vector 2: Minimal DataAssertionLogEntry CBOR

Input:
```
field 2: [1700000000, 1700003600]
field 3: 1
field 4: {"claim": "test-value"}
```

Deterministic CBOR (RFC 8949 §4.2), hex:
```
a302821a6553f1001a6553ff10030104a165636c61696d6a746573742d76616c7565
```

With `entry_type_byte` prefix (0x01), full TBS:
```
01a302821a6553f1001a6553ff10030104a165636c61696d6a746573742d76616c7565
```

`entry_hash = SHA-256(0x00 ‖ tbs)`:
```
56ebd28ff0cdbff1d889e39d2df45caf3c2755215f1e712d284996759794952b
```

### Vector 3: null_entry hash

```
tbs = 0x00
entry_hash = SHA-256(0x00 || 0x00) = 96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7
```

### Vector 4: Four-Entry Merkle Tree

Leaf hashes (SHA-256(0x00 ‖ data), data = literal ASCII label bytes):

```
H0 = SHA-256(0x00 || "entry0") = 59655a8fc43a4bac74f361137f85369f0fbea03c80ff997aeb2501e9751f069a
H1 = SHA-256(0x00 || "entry1") = c0df96a27e09112cc9a8cf96a77a7dd1b5dd6d270e1bd78293768fd870932b24
H2 = SHA-256(0x00 || "entry2") = fe7a9baff2bddf061ca8b01dadcd1a1f05bfa35efcdc940f8c8eaaa08091718c
H3 = SHA-256(0x00 || "entry3") = 2412d86c18041cd64c3fdc81972ddc57214b40faa7fb3d18763a07764b0325e6
```

Internal nodes:
```
H01  = SHA-256(0x01 || H0 || H1)   = 60518c902a1ca57829622658ac4351c377d458553ad2d7e6bf8b2136790ac680
H23  = SHA-256(0x01 || H2 || H3)   = 58ddae035f3886d17b1a289d0bcb14b2ff771a1fcb6fe30d69b54874fd3f53a1
root = SHA-256(0x01 || H01 || H23) = 8d45df940b83df505f79895a6327298d5ed3392b105468c06c25fda1cb5cba7d
```

Inclusion proof for `entry_index=2`, `tree_size=4`:
```
proof[0] = 2412d86c...  (H3, right sibling — index=2 is even, current is left child)
proof[1] = 60518c90...  (H01, left uncle — index=1 is odd, current is right child)
```

Verification path:
```
start:    H2,   index=2 (even): node = SHA-256(0x01 || H2 || proof[0]) = H23
          H23,  index=1 (odd):  node = SHA-256(0x01 || proof[1] || H23) = root ✓
```

### Signing Vectors

**Ed25519** — private seed `4242...42` (32 bytes, all 0x42):

```
public_key:    2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
message_hex:   (checkpoint body from Vector 1)
signature_hex: 3a2164be5c7711f662358de3dc330290252ec46f4b2d78e8381a13a31af4b9dd
               924e6b14f23cab58a7b9194b5af8732ff6ad1572d59a24fba3c952dd4559f206
```

Ed25519 signatures are deterministic. Both implementations must produce this
exact signature for this seed and message.

**ECDSA P-256** — private scalar = SHA-256(`"mta-qr-test-ecdsa-scalar"`) mod n:

```
scalar_hex:        0d5eb4b74e79178fee763e9e39f5c5101f5b5c722db72dbd48295bf0a55e5868
public_key_hex:    04eef2d56038bed8a66c23a9c25a1aa741348f718abf4094f70b55033a00f8e8
                   3a6ad8694ac8c28b5165397839671114b19ffbd55b8d95b858a698e74944692b85
message_hex:       (checkpoint body from Vector 1 — same bytes as Ed25519 message)
pre_recorded_sig:  ed35a79eaebce59251a96ff9eea39aa3d7f5cc814c234f0252b2d4538d59e844
                   9e42de4427742790557ea95bd7b4daea81db81748c2bbf4f70375633248ef1fb
```

Public key encoding: uncompressed, `0x04 ‖ X ‖ Y`, 65 bytes. Implementations
MUST derive this exact public key from this scalar. ECDSA signing is randomized;
the `pre_recorded_sig` above was produced by the Go reference implementation.
Interop test: verify `pre_recorded_sig` with both implementations using
`public_key_hex` — both MUST return true. Additionally, each implementation
signs independently and the other's verify function MUST accept that signature.

---

## Open Questions

### Blocking — Required Before Interoperable Deployment

**Note signature type registration — deployment blocker for ECDSA and FN-DSA.**
Before any MTA-QR implementation can use ECDSA P-256, ECDSA P-384, or FN-DSA-512
for checkpoint signing, a note signature algorithm type must be registered for
each at C2SP. Ed25519 (`sig_alg=6`) is fully specified and not blocked.
ML-DSA-44 (`sig_alg=1`) is implemented in all four reference implementations (Go via cloudflare/circl; TypeScript via @noble/post-quantum; Rust via the ml-dsa crate; Java via BouncyCastle 1.79+ MLDSAKeyPairGenerator). It also requires C2SP note signature registration before it can interoperate with standard tlog-checkpoint parsers.

For ECDSA P-256 and P-384, the registration must specify:
- Note verifier key name format for ECDSA public keys (uncompressed point, base64-encoded)
- Key ID derivation (SHA-256 of key name without keyid component, first 4 bytes)
- Signature encoding: raw r‖s (IEEE P1363) base64-encoded in note signature lines
- Signed message format: same checkpoint body as Ed25519 signatures

For ML-DSA-44 and FN-DSA-512, additionally:
- How the 1312-byte (ML-DSA-44) or 897-byte (FN-DSA-512) public key is base64-encoded in the key name
- How the fixed-size (ML-DSA-44: 2420 bytes) or variable-length (FN-DSA-512) signature is base64-encoded in note lines

Until these registrations exist, ECDSA, ML-DSA-44, and FN-DSA checkpoint signatures
cannot interoperate with standard tlog-checkpoint parsers. The ECDSA registration
is the more urgent dependency. The MTC authors and c2sp.org maintainers are the
right people to engage on these PRs.

**Revocation format: specified, not yet implemented.** The revocation wire
format, filter cascade construction, delta update protocol, and verifier behavior
are now defined in the Revocation section. The reference implementations emit
a documented stub ("not implemented") for the revocation check step. Implementing
the Bloom filter cascade and delta distribution is the primary remaining v1 task
for the SDK layer. The Mozilla CRLite implementation (github.com/mozilla/crlite,
MPL-2.0) is the reference for the cascade construction.

### Non-Blocking — Required Before v1 Finalization

**Schema registry.** `schema_id` is a uint in the CBOR entry. Recommended
derivation: SHA-256 of the reverse-domain schema name string, first 4 bytes as
big-endian uint32. Issuers MUST publish their schema name strings alongside
their log origin configuration. A stable registry is needed for v1.

**Attestation format registry governance.** The attestation_format registry
needs a home (IANA, C2SP, or similar). Value 255 provides an escape hatch so
registry gaps don't block deployment.

**Key assertion challenge-response protocol.** The spec defines the log entry
format and possession proof requirement for Type 0x02 assertions, but the
challenge-response protocol is schema-defined and out of scope here. No two
independent Type 0x02 implementations will interoperate without a separate
protocol spec.

### Long-Horizon

**PQ witness cosignatures.** The tlog-cosignature/v1 spec mandates Ed25519 for
witness keys. A future v2 will need PQ witness key types. Ed25519 witnesses are
adequate for the transparency function in the near term — compromising the
transparency guarantee requires compromising multiple independent witness
operators simultaneously, which is a much harder attack than breaking a single
issuer key. Witnesses verify consistency before cosigning as a protocol
requirement, not a behavioral assumption.

---

## Appendix A: Classical and Transition Profiles

*Informational. Not normative.*

### Classical Profile (WebCrypto-Compatible Today)

**Recommended starting algorithm: Ed25519 (`sig_alg=6`).** Ed25519 is the only
`sig_alg` value with a complete C2SP note signature registration today. ECDSA
P-256 (`sig_alg=4`) is the recommended classical alternative once its C2SP
registration lands.

A deployment using Ed25519 or ECDSA P-256 as the issuer signing algorithm gets
the full MTA-QR security model using only WebCrypto APIs. The only property not
provided is quantum resistance of the issuer signature.

**What you can build today with WebCrypto only:**

- Full issuer implementation: sign checkpoints with `crypto.subtle.sign`, compute
  Merkle roots with `crypto.subtle.digest`.
- Full Mode 1 verifier: fetch checkpoint, verify issuer ECDSA/Ed25519 signature,
  verify Ed25519 witness cosignatures, verify inclusion proof, check expiry and
  revocation.
- Full Mode 0 verifier (classical): all offline, all WebCrypto.

Ed25519 witness cosignature verification requires Chrome 113+, Firefox 130+,
Safari 17+, Node 20+. For environments that cannot guarantee these versions,
a small Ed25519 polyfill (e.g. noble-ed25519) is the only external dependency.

FN-DSA, ML-DSA, and SLH-DSA verification requires a WASM cryptographic library
in any environment.

### Recommended Deployment Progression

| Phase | Issuer sig_alg | Mode | Notes |
|-------|---------------|------|-------|
| **Start** | Ed25519 (6) | 1 or 0 | **Recommended starting algorithm.** Fully specified today; no C2SP registration blocker |
| Start (future) | ECDSA P-256 (4) | 1 or 0 | Full WebCrypto; available once C2SP registration resolved |
| Transition | ECDSA P-256 + FN-DSA-512 dual_sig | 1 | Both classical and PQC readers supported |
| PQC-ready | FN-DSA-512 (0) | 1 or 0 | Quantum-resistant; WASM required for verification |

### Migration Path to PQC

Migration from classical to PQC issuer requires no changes to the log structure,
CBOR entry format, QR payload layout, or witness infrastructure. The only changes
are: generate a PQC key pair; update the trust configuration distributed to
readers; begin signing new checkpoints with the PQC key; optionally run dual
signatures during the transition window; retire the classical key once all
outstanding classical-signed assertions have expired.

---

## Appendix B: QR Encoding Requirements

*Informational. Not normative.*

MTA-QR payloads MUST be encoded using QR binary/byte mode (mode indicator `0100`
per ISO/IEC 18004:2015). The minimum error correction level for physical
deployments is M (~15% recovery). All size estimates in this spec use M ECC.

For Mode 0 deployments using Version 40, issuers MUST specify and enforce:
- Minimum print resolution: 300 DPI
- Minimum label size: 61mm × 61mm
- Quiet zone: enforced in print template
- Scanner qualification: decode success rate > 99% under expected conditions

For Mode 0 payloads approaching the capacity of a single Version 40 symbol,
splitting across two Version 25–28 symbols using Structured Append is preferred.
For deployments targeting consumer phone cameras, single-symbol Mode 1 is the
more reliable choice.

---

## Appendix C: High-Frequency Issuance and Log Pruning

*Informational. Not normative.*

High-volume use cases (membership systems, transit passes) are handled through
short validity windows — which bound the live working set — and log pruning per
MTC draft-09 §5.6.1, which removes entries older than the minimum index without
breaking consistency proofs.

For a membership system rotating QR codes every 5 minutes, with 30-second
checkpointing: any fresh assertion is covered by the next checkpoint within 30
seconds. The live log is roughly the last 10–15 minutes of entries, keeping log
size proportional to assertion lifetime and issuance rate rather than total
historical volume.
