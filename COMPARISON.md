# QR Code Authentication — Approach Comparison

Authenticating a QR code means answering two questions at scan time: did a
legitimate issuer produce this, and is it still valid? Four approaches have seen
real deployment at scale. Each makes different tradeoffs.

---

## The four approaches

**HMAC.** A MAC over the payload using a shared secret. Issuer and all verifiers
hold the same key. The issuer and verifier must be the same party or operate
under tight shared control. Any holder of the secret can also forge codes.

**Per-assertion signature.** Each payload is individually signed by the issuer's
private key. The EU Digital COVID Certificate used this at continental scale:
COSE signatures over CBOR health data, national keys federated through an EU
gateway, verifier apps across 60+ countries with no per-scan coordination.

**Rotating barcode.** A time-based token derived from a server-side secret
regenerates every 15 to 30 seconds, making screenshots useless. Ticketmaster
SafeTix and AXS operate this way. Verification requires contacting the issuer's
servers at or before scan time.

**MTA-QR.** Each payload carries a Merkle inclusion proof against a
transparency log checkpoint. The issuer signs the checkpoint; independent
witnesses cosign it. Verifiers cache the checkpoint during a connectivity window
and verify entirely offline against the cache.

---

## Credential lifetime

HMAC and rotating barcodes are session-oriented mechanisms. They have no
persistent credential object and no mechanism for long-term validity,
revocation, or audit. They are appropriate for short-lived contexts — entry
tokens, event access — where the issuer controls both sides of the transaction
and validity windows are measured in minutes to hours.

Per-assertion signatures produce a persistent signed object that can be verified
independently of the issuer at any point during its validity window. This is what
made the COVID certificate useful: a certificate issued in one country could be
verified in another months later with no connection to the issuing authority.
The limitation for long-lived credentials is revocation. Revoking an offline
bearer token requires pushing revocation state to every verifier, which the
COVID system found painful in practice.

MTA-QR supports short, medium, and long credential lifetimes. TTL-based expiry
handles short-lived tokens. For medium and long-lived credentials, the protocol
provides explicit revocation: the issuer publishes revocation ranges via
`GET /revoked`, and verifiers check `entry_index` against those ranges as part
of normal verification. Because revocation is distributed on the same charge-cycle
schedule as checkpoint updates, it inherits the same delivery model as the
checkpoint — no special infrastructure required. For credentials that must
remain verifiable over years, the post-quantum signing posture also matters:
a credential issued today under a classical algorithm may need to be verifiable
long after quantum computers make that algorithm breakable.

---

## Comparison

| Property | HMAC | Per-assertion sig | Rotating barcode | MTA-QR |
|---|---|---|---|---|
| Short-lived credentials | Yes | Yes | Yes | Yes |
| Medium and long-lived credentials | No | Partial | No | Yes |
| Auditable revocation | No | No | No | Yes |
| Post-quantum safe | Yes | No | Yes | Yes |
| PQC migration needs only a key update, not a new protocol | n/a | No | n/a | Yes |
| PQC signature fits in QR payload | n/a | No | n/a | Yes |
| Unauthorized issuance is detectable | No | No | No | Yes |
| All verifiers see the same log (split-view prevented) | No | No | No | Yes |
| Issued content is bound to the log entry | No | No | No | Yes |
| Algorithm downgrade is structurally prevented | No | No | No | Yes |
| Trusted issuer set is explicit and auditable | No | No | No | Yes |
| Key compromise enables undetected forgery | Yes | Yes | No | No |
| Issuer and verifier can be independent | No | Yes | No | Yes |
| Offline at scan time | Yes | Yes | No | Yes |
| Prevents screenshot reuse | No | No | Yes (sub-minute) | Yes (TTL-controlled)¹ |
| Deployment complexity | Low | Low | Medium | Medium |
| Standards maturity | None | Mature (EUDCC) | Proprietary (SafeTix) | None |

¹ The `expiry_time` field in each payload controls the validity window. Issuers
select TTLs appropriate to their use case. A five-minute TTL prevents a
screenshot being sold to a second buyer for any event where entry happens within
a defined window. Rotating barcodes provide a fixed sub-minute window regardless
of use case. Single-use enforcement within the TTL window requires deduplication
at the verifier.

---

## Key observations

**PQC breaks per-assertion signing for QR codes.** Classical signatures (Ed25519,
ECDSA P-256) are 64 bytes. NIST-standardized replacements are not. ML-DSA-44
(FIPS 204) produces 2,420-byte signatures. FN-DSA-512 (FIPS 206) produces
signatures up to 666 bytes and sits at the absolute boundary of what Version 40
QR at Medium ECC (~1,230–1,250 usable bytes) can carry — with almost no room
left for assertion content. There is no viable migration path that keeps the
per-assertion model inside QR payload limits. MTA-QR avoids this by signing the
checkpoint rather than each payload; the issuer signature never appears in the
QR code regardless of algorithm.

**Rotating barcodes trade verifier independence for a fixed sub-minute screenshot
window.** The server dependency is an architectural commitment, not just an
operational one. It means no third party can build a scanner without the
issuer's ongoing cooperation, and the issuer can admit or deny any credential
server-side without an auditable record. MTA-QR provides screenshot resistance
through issuer-controlled TTLs. For most deployment contexts the difference
between a 30-second and a five-minute validity window is not material; the
rotating barcode model is only preferable when a sub-minute window is a hard
requirement.

**Key compromise looks very different across approaches.** The COVID certificate
system experienced real key compromise: forged French vaccination certificates
circulated after a test key reached production. Revoking offline bearer tokens
required pushing updates to every verifier app in 60+ countries. MTA-QR makes
compromise detectable earlier — the log is public and witnessed — and limits
scope: the witness quorum must also be compromised to issue forged checkpoints.
Offline verification means revocation propagation is still a deployment concern
that must be designed for, on the same schedule as checkpoint updates.

**The witness quorum prevents split-view attacks.** Witnesses only cosign a
checkpoint after verifying it is consistent with all previous checkpoints they
have seen for that log. A verifier holding a checkpoint with a valid quorum
knows it is seeing the same log as every other verifier that trusts those
witnesses. Per-assertion signatures provide no equivalent guarantee.

**Issued content is cryptographically bound to the log.** The Merkle proof ties
a specific payload to the signed checkpoint root. The issuer cannot produce a
valid proof for content that was never logged, and cannot retroactively claim
a different payload was issued for a given entry. Per-assertion signatures prove
the issuer signed something but do not prove it was recorded anywhere.

**The trust model is explicit and closed.** Each verifier is configured with a
specific issuer origin and algorithm. There is no certificate chain and no
ambient trust inheritance. A verifier configured for Ed25519 from a given origin
will reject any payload claiming that origin under a different algorithm. The
set of trusted issuers is fully auditable at the verifier.

---

## Considerations for choosing

**Per-assertion Ed25519** has mature tooling, a proven track record at scale,
and no infrastructure requirements beyond key management. The limitation is the
PQC migration path. When post-quantum signing becomes a requirement, the
per-assertion model does not fit within QR payload constraints and a different
architecture is needed.

**MTA-QR** fits deployments where post-quantum signing is on the roadmap, where
issuer accountability and log auditability matter, where credentials span medium
or long validity windows, or where verifier independence is a hard requirement.
The tradeoff is medium deployment complexity and the need for a pre-provisioned
trust configuration on each verifier.

The two are not mutually exclusive. MTA-QR supports Ed25519 today. A deployment
can run Ed25519 and migrate to ML-DSA-44 by updating the trust configuration and
issuer key, with no changes to verifier code or the wire format.

**Rotating barcodes** fit deployments where preventing screenshot transfer is
the primary concern, credentials are short-lived, and the issuer operates both
sides of the transaction.

---

## Limitations of this comparison

The comparison reflects the current protocol design (v0.1). Several properties
marked as MTA-QR advantages depend on features that are defined in the spec but
not yet fully implemented in this reference SDK:

- **Auditable revocation** requires a defined revocation list format. The
  `GET /revoked` URL convention is established but the response format and
  signing requirement are open items. See SPEC.md §Open Questions.
- **Mode 0 (fully offline)** is not yet implemented in the server-side verifiers.
  The browser demo and SDK implement Mode 0 verification.
- **Post-quantum interoperability with the witness network** requires C2SP note
  signature type registrations for ML-DSA-44 and FN-DSA-512 that do not exist
  yet. Ed25519 is the only algorithm with full witness network interop today.

See [README.md](README.md#known-limitations) for the current implementation
status of each feature.
