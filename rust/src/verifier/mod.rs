//! MTA-QR Verifier.
//!
//! Verifies QR code payloads against a loaded [`TrustConfig`]. No key custody
//! required — verification is pure crypto.

use crate::trust::TrustConfig;
use crate::signing::{verify::verify, ALG_ED25519};
use crate::issuer::{
    hash_leaf, merkle_root, compute_root_from_proof, verify_inclusion,
    checkpoint_body, cosignature_message,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

// BATCH_SIZE is read from trust.batch_size at verification time (see Verifier::verify)
const GRACE:      u64   = 600;

/// The result of a successful verification.
#[derive(Debug, Clone)]
pub struct VerifyOk {
    /// Payload mode. 1 = Mode 1 (inclusion proof verified).
    /// 2 = Mode 2 (inclusion NOT verified — proof must be fetched from a tile server).
    pub mode:        u8,
    pub entry_index: u64,
    pub tree_size:   u64,
    pub origin:      String,
    pub schema_id:   u64,
    pub issued_at:   u64,
    pub expires_at:  u64,
    pub claims:      HashMap<String, serde_json::Value>,
}

/// Why a verification failed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("verify: {failed_step}: {reason}")]
pub struct VerifyFail {
    pub failed_step: String,
    pub reason:      String,
}

/// A single step in a verification trace.
#[derive(Debug, Clone)]
pub struct VerifyStep {
    pub name:   String,
    pub ok:     bool,
    pub detail: String,
}

/// Full trace result — always has steps; exactly one of `ok`/`fail` is `Some`.
#[derive(Debug)]
pub struct TraceResult {
    pub ok:    Option<VerifyOk>,
    pub fail:  Option<VerifyFail>,
    pub steps: Vec<VerifyStep>,
}

impl TraceResult {
    pub fn is_valid(&self) -> bool { self.ok.is_some() }
}

/// A function that provides checkpoint notes without HTTP. Used in tests.
pub type NoteProvider        = Box<dyn Fn(&str) -> Result<String> + Send + Sync>;
/// Provides revocation artifacts without HTTP. Used in tests.
pub type RevocationProvider  = Box<dyn Fn(&str) -> Result<String> + Send + Sync>;

/// Cached revocation artifact per origin.
struct CachedRevocation {
    cascade:   crate::cascade::Cascade,
    tree_size: u64,
}

/// The MTA-QR verifier.
pub struct Verifier {
    anchors:             HashMap<u64, TrustConfig>,
    note_provider:       Option<NoteProvider>,
    revocation_provider: Option<RevocationProvider>,
    cache:               Mutex<(VecDeque<String>, HashMap<String, Vec<u8>>)>,
    revoc_cache:         Mutex<HashMap<String, CachedRevocation>>,
}

impl Verifier {
    /// Create a Verifier from a trust config.
    /// Create an empty multi-anchor Verifier.
    pub fn new() -> Self {
        Self { anchors: HashMap::new(), note_provider: None, revocation_provider: None,
               cache: Mutex::new((VecDeque::new(), HashMap::new())),
               revoc_cache: Mutex::new(HashMap::new()) }
    }

    /// Create a Verifier with a note provider (for tests — bypasses HTTP).
    pub fn with_note_provider(provider: NoteProvider) -> Self {
        let mut v = Self::new();
        v.note_provider = Some(provider);
        v
    }

    /// Create a Verifier with note and revocation providers (for tests).
    pub fn with_revocation_provider(note: NoteProvider, revoc: RevocationProvider) -> Self {
        let mut v = Self::new();
        v.note_provider       = Some(note);
        v.revocation_provider = Some(revoc);
        v
    }

    /// Register a trusted issuer. Returns `&mut self` for chaining.
    /// Returns an error if the 8-byte origin_id collides with a different origin.
    pub fn add_anchor(&mut self, trust: TrustConfig) -> anyhow::Result<&mut Self> {
        if let Some(existing) = self.anchors.get(&trust.origin_id) {
            if existing.origin != trust.origin {
                return Err(anyhow!("origin_id collision: 0x{:016x} shared by {:?} and {:?}",
                    trust.origin_id, existing.origin, trust.origin));
            }
        }
        self.anchors.insert(trust.origin_id, trust);
        Ok(self)
    }

    /// All registered anchors.
    pub fn anchors(&self) -> Vec<&TrustConfig> { self.anchors.values().collect() }

    /// Verify a QR code payload. Returns `Ok(VerifyOk)` or `Err(VerifyFail)`.
    pub async fn verify(&self, payload: &[u8]) -> Result<VerifyOk, VerifyFail> {
        let tr = self.verify_with_trace(payload).await;
        match (tr.ok, tr.fail) {
            (Some(ok), _) => Ok(ok),
            (_, Some(fail)) => Err(fail),
            _ => unreachable!(),
        }
    }

    /// Verify a payload and return the full step trace.
    pub async fn verify_with_trace(&self, payload_bytes: &[u8]) -> TraceResult {
        let mut steps = vec![];

        macro_rules! add {
            ($ok:expr, $name:expr, $detail:expr) => {
                steps.push(VerifyStep { name: $name.into(), ok: $ok, detail: $detail.into() });
            };
        }
        macro_rules! fail {
            ($step:expr, $reason:expr) => {{
                add!(false, $step, $reason);
                return TraceResult {
                    ok: None,
                    fail: Some(VerifyFail { failed_step: $step.into(), reason: $reason.into() }),
                    steps,
                };
            }};
        }

        // 1. Decode payload
        let p = match decode_payload(payload_bytes) {
            Ok(p) => p,
            Err(e) => fail!("decode payload", format!("malformed: {e}")),
        };
        add!(true, "decode payload", format!(
            "mode={} sig_alg={} entry_index={} tree_size={}",
            p.mode, p.sig_alg, p.entry_index, p.tree_size));

        // 2. Reject null entry
        if p.entry_index == 0 { fail!("entry index", "entry_index=0 is reserved for null_entry"); }
        add!(true, "entry index", format!("entry_index={} valid", p.entry_index));

        // 3. Mode 0 — verify the embedded checkpoint directly from payload bytes.
        if p.mode == 0 {
            // Null-entry check applies to all modes.
            if p.entry_index == 0 { fail!("entry index", "entry_index=0 is reserved for null_entry"); }
            add!(true, "entry index", format!("entry_index={} valid", p.entry_index));
            // Trust anchor lookup.
            let trust = match self.anchors.get(&p.origin_id) {
                Some(t) => t,
                None => fail!("trust anchor", format!(
                    "no anchor for origin_id 0x{:016x} — call add_anchor() first", p.origin_id)),
            };
            add!(true, "trust anchor", format!("found: {:?}", trust.origin));
            // Algorithm binding.
            if p.sig_alg != trust.sig_alg {
                fail!("algorithm binding", format!(
                    "payload sig_alg={} but trust config requires {}", p.sig_alg, trust.sig_alg));
            }
            add!(true, "algorithm binding", format!("sig_alg={} matches", p.sig_alg));
            // Verify embedded checkpoint.
            let root_hash = match self.verify_embedded_checkpoint(&p, trust) {
                Ok(rh) => { add!(true, "embedded checkpoint",
                    format!("issuer sig ✓ · {}/{} witnesses ✓", trust.witness_quorum, trust.witness_quorum));
                    rh },
                Err(e) => fail!("embedded checkpoint", e.to_string()),
            };
            // Continue with inclusion proof and claims checks.
            return self.run_after_root_hash(&p, &root_hash, trust, steps).await;
        }

        // 4. Trust anchor lookup — multi-anchor routing by origin_id.
        let trust = match self.anchors.get(&p.origin_id) {
            Some(t) => t,
            None => fail!("trust anchor", format!(
                "no anchor for origin_id 0x{:016x} — call add_anchor() first", p.origin_id)),
        };
        add!(true, "trust anchor", format!("found: {:?}", trust.origin));

        // 5. Self-describing origin consistency
        if let Some(ref env_origin) = p.origin {
            if env_origin != &trust.origin {
                fail!("origin consistency", format!("envelope {:?} != trust config {:?}", env_origin, trust.origin));
            }
            add!(true, "origin consistency", "envelope matches trust config");
        }

        // 6. Algorithm binding
        if p.sig_alg != trust.sig_alg {
            fail!("algorithm binding", format!("payload sig_alg={} but trust config requires {}", p.sig_alg, trust.sig_alg));
        }
        add!(true, "algorithm binding", format!("sig_alg={} matches trust config", p.sig_alg));

        // 7. Checkpoint resolution
        let cache_key = format!("{}:{}", trust.origin, p.tree_size);
        let cached_root = self.cache.lock().unwrap().1.get(&cache_key).cloned();

        let root_hash = if let Some(r) = cached_root {
            add!(true, "checkpoint", format!("cache hit · tree_size={}", p.tree_size));
            r
        } else {
            add!(false, "checkpoint", format!("cache miss · fetching {}", trust.checkpoint_url));
            match self.fetch_and_verify_checkpoint(p.tree_size, trust).await {
                Ok((root, fetched_size)) => {
                    add!(true, "checkpoint fetch", format!(
                        "issuer sig ✓ · {}/{} witnesses ✓ · tree_size={}",
                        trust.witness_quorum, trust.witness_quorum, fetched_size));
                    {
                        const MAX_CACHE_ENTRIES: usize = 1000;
                        let mut guard = self.cache.lock().unwrap();
                        let (order, map) = &mut *guard;
                        if !map.contains_key(&cache_key) {
                            if order.len() >= MAX_CACHE_ENTRIES {
                                if let Some(oldest) = order.pop_front() {
                                    map.remove(&oldest);
                                }
                            }
                            order.push_back(cache_key.clone());
                        }
                        map.insert(cache_key, root.clone());
                    }
                    root
                }
                Err(e) => fail!("checkpoint fetch", e.to_string()),
            }
        };

        return self.run_after_root_hash(&p, &root_hash, trust, steps).await;
    }

    /// Verify a Mode 0 embedded checkpoint and return the root hash.
    fn verify_embedded_checkpoint(&self, p: &DecodedPayload, trust: &TrustConfig) -> Result<[u8; 32]> {
        let root_hash = p.root_hash.ok_or_else(|| anyhow!("root_hash missing in Mode 0 payload"))?;
        let issuer_sig = p.issuer_sig.as_ref().ok_or_else(|| anyhow!("issuer_sig missing"))?;
        let body = checkpoint_body(&trust.origin, p.tree_size, &root_hash);
        if !verify(trust.sig_alg, &body, issuer_sig, &trust.issuer_pub_key) {
            return Err(anyhow!("{} issuer signature invalid", trust.issuer_key_name));
        }
        let mut seen: std::collections::HashSet<[u8; 4]> = Default::default();
        let mut verified = 0usize;
        for cosig in &p.cosigs {
            if !seen.insert(cosig.key_id) {
                return Err(anyhow!("duplicate witness key_id {:02x?}", cosig.key_id));
            }
            let msg = cosignature_message(&body, cosig.timestamp);
            for w in &trust.witnesses {
                if w.key_id != cosig.key_id { continue; }
                if verify(ALG_ED25519, &msg, &cosig.signature, &w.pub_key) {
                    verified += 1; break;
                }
            }
        }
        if verified < trust.witness_quorum {
            return Err(anyhow!("witness quorum not met: {}/{}", verified, trust.witness_quorum));
        }
        Ok(root_hash)
    }

    /// Run entry-hash, inclusion-proof, TBS, revocation and expiry checks.
    async fn run_after_root_hash(
        &self, p: &DecodedPayload, root_hash: &[u8],
        trust: &TrustConfig, mut steps: Vec<VerifyStep>,
    ) -> TraceResult {
        macro_rules! add {
            ($ok:expr, $step:expr, $detail:expr) => {
                steps.push(VerifyStep { name: $step.into(), ok: $ok, detail: $detail.into() });
            };
        }
        macro_rules! fail {
            ($step:expr, $reason:expr) => {{
                add!(false, $step, $reason);
                return TraceResult {
                    ok: None,
                    fail: Some(VerifyFail { failed_step: $step.into(), reason: $reason.into() }),
                    steps,
                };
            }};
        }
        // 7. Entry hash
        let e_hash = hash_leaf(&p.tbs);
        add!(true, "entry hash", format!("SHA-256(0x00 || tbs) = {}…", hex::encode(&e_hash[..8])));

        // 8. Merkle inclusion proof — behaviour depends on mode.
        if p.mode == 2 {
            // Mode 2 (online): NO INCLUSION PROOF IS VERIFIED HERE.
            // The payload carries no proof hashes. A production scanner fetches
            // proof tiles from a tile server and verifies inclusion at scan time.
            // This SDK has no tile server — it only validates entry_index < tree_size.
            // Do not treat a Mode 2 VerifyOk as proof of inclusion.
            if p.entry_index >= p.tree_size {
                fail!("inclusion proof",
                    format!("mode=2: entry_index={} >= tree_size={}", p.entry_index, p.tree_size));
            }
            add!(true, "inclusion proof", format!(
                "mode=2 (online): entry_index={} < tree_size={} · proof fetched at scan time",
                p.entry_index, p.tree_size));
        } else {
            // Mode 1 (cached): two-phase tiled Merkle proof embedded.
            let global_idx   = p.entry_index as usize;
            let batch_size   = trust.batch_size;
            let inner_idx    = global_idx % batch_size;
            let batch_idx    = global_idx / batch_size;
            let num_batches  = (p.tree_size as usize + batch_size - 1) / batch_size;
            let batch_start  = batch_idx * batch_size;
            let this_batch_sz = batch_size.min(p.tree_size as usize - batch_start);

            let inner_proof: Vec<_> = p.proof_hashes[..p.inner_count as usize].to_vec();
            let outer_proof: Vec<_> = p.proof_hashes[p.inner_count as usize..].to_vec();

            let batch_root = match compute_root_from_proof(&e_hash, inner_idx, this_batch_sz, &inner_proof) {
                Ok(r) => r,
                Err(e) => fail!("inclusion proof", format!("phase A (inner) failed: {e}")),
            };
            if let Err(e) = verify_inclusion(&batch_root, batch_idx, num_batches, &outer_proof, &root_hash) {
                fail!("inclusion proof", format!("phase B (outer) failed: {e}"));
            }
            add!(true, "inclusion proof", format!(
                "phase A: {} hashes → batch root ✓ · phase B: {} hashes → parent root ✓",
                inner_proof.len(), outer_proof.len()));
        }

        // 9. Entry type
        if p.tbs.len() < 2 || p.tbs[0] != 0x01 {
            fail!("tbs decode", format!("entry_type must be 0x01, got 0x{:02x}", p.tbs.first().copied().unwrap_or(0)));
        }
        add!(true, "tbs decode", "entry_type=data_assertion");

        // 10. CBOR decode
        let (issued_at, expires_at, schema_id, claims) = match decode_tbs(&p.tbs[1..]) {
            Ok(v) => v,
            Err(e) => fail!("cbor decode", e.to_string()),
        };
        add!(true, "cbor decode", format!("schema_id={schema_id} issued={issued_at} expires={expires_at}"));

        // 10. Revocation check — SPEC.md §Revocation.
        {
            let revoc = self.check_revocation(p.entry_index, p.tree_size, trust).await;
            match revoc {
                Ok(ref msg)  => { add!(true,  "revocation check", msg.as_str()); }
                Err(ref msg) => { fail!("revocation check", msg.as_str()); }
            }
        }

        // 11. Expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if expires_at + GRACE < now {
            fail!("expiry", format!("expired: expiry={expires_at} now={now}"));
        }
        add!(true, "expiry", format!("valid · {}s remaining", expires_at as i64 - now as i64));

        add!(true, "complete", format!(
            "all checks passed · entry_index={} · origin={:?}", p.entry_index, trust.origin));

        TraceResult {
            ok: Some(VerifyOk {
                mode:        p.mode,
                entry_index: p.entry_index,
                tree_size:   p.tree_size,
                origin:      trust.origin.clone(),
                schema_id,
                issued_at,
                expires_at,
                claims,
            }),
            fail: None,
            steps,
        }
    
    }

    async fn fetch_and_verify_checkpoint(&self, required_size: u64, trust: &TrustConfig) -> Result<(Vec<u8>, u64)> {
        let note = if let Some(ref provider) = self.note_provider {
            provider(&trust.checkpoint_url)?
        } else {
            #[cfg(feature = "goodkey")]
            {
                // 10-second timeout prevents indefinite hangs on slow issuers.
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?;
                let resp = client.get(&trust.checkpoint_url).send().await
                    .map_err(|e| anyhow!("GET {}: {e}", trust.checkpoint_url))?;
                // Cap to 64 KB — a valid checkpoint is ~200 bytes.
                // A malicious issuer serving a gigabyte response would otherwise
                // exhaust verifier memory.
                let bytes = resp.bytes().await
                    .map_err(|e| anyhow!("read checkpoint: {e}"))?;
                if bytes.len() > 64 * 1024 {
                    return Err(anyhow!("checkpoint response too large ({} bytes)", bytes.len()));
                }
                String::from_utf8(bytes.to_vec())
                    .map_err(|e| anyhow!("checkpoint not valid UTF-8: {e}"))?
            }
            #[cfg(not(feature = "goodkey"))]
            {
                return Err(anyhow!(
                    "no note provider and HTTP not available without 'goodkey' feature"
                ));
            }
        };
        self.verify_note(&note, required_size, trust)
    }

    fn verify_note(&self, note: &str, required_size: u64, trust: &TrustConfig) -> Result<(Vec<u8>, u64)> {
        let blank = note.find("\n\n")
            .ok_or_else(|| anyhow!("note missing blank-line separator"))?;
        let body: Vec<u8> = (note[..blank].to_string() + "\n").into_bytes();
        let rest = &note[blank + 2..];

        // Parse body
        let body_str = std::str::from_utf8(&body)?;
        let lines: Vec<&str> = body_str.trim_end_matches('\n').splitn(3, '\n').collect();
        // Per c2sp.org/tlog-checkpoint: three mandatory lines plus optional extension lines.
        if lines.len() < 3 { return Err(anyhow!("checkpoint body must have at least 3 lines, got {}", lines.len())); }
        let note_origin  = lines[0];
        let tree_size: u64 = lines[1].parse()?;
        let root_hash    = B64.decode(lines[2])?;

        if note_origin != trust.origin {
            return Err(anyhow!("origin mismatch: {:?}", note_origin));
        }
        if tree_size < required_size {
            return Err(anyhow!("tree_size {tree_size} < required {required_size}"));
        }

        let sig_lines: Vec<&str> = rest.lines().filter(|l| !l.trim().is_empty()).collect();

        // Issuer sig — dispatch by key name, skip 4-byte key_hash prefix
        let mut issuer_ok = false;
        for line in &sig_lines {
            if !line.contains(&trust.issuer_key_name) { continue; }
            if let Some(raw) = last_field_base64(line) {
                if raw.len() < 4 { continue; }
                // Per c2sp.org/signed-note: first 4 bytes are key_hash; rest is sig.
                let raw_sig = &raw[4..];
                if verify(trust.sig_alg, &body, raw_sig, &trust.issuer_pub_key) {
                    issuer_ok = true;
                    break;
                }
            }
        }
        if !issuer_ok { return Err(anyhow!("issuer signature not found or invalid")); }

        // Witness cosigs — always Ed25519
        // Per c2sp.org/signed-note + tlog-cosignature:
        //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes
        let mut verified: HashSet<String> = HashSet::new();
        for line in &sig_lines {
            if let Some(raw) = last_field_base64(line) {
                if raw.len() != 76 { continue; }
                let key_hash = &raw[0..4];
                let ts = u64::from_be_bytes(raw[4..12].try_into().unwrap());
                let wsig = &raw[12..76];
                let msg = cosignature_message(&body, ts);
                for w in &trust.witnesses {
                    if w.key_id != key_hash { continue; }
                    if verify(ALG_ED25519, &msg, wsig, &w.pub_key) {
                        verified.insert(w.name.clone());
                    }
                }
            }
        }
        if verified.len() < trust.witness_quorum {
            return Err(anyhow!("witness quorum not met: {}/{}", verified.len(), trust.witness_quorum));
        }

        Ok((root_hash, tree_size))
    }
    /// Revocation check — SPEC.md §Revocation — Verifier Behavior.
    async fn check_revocation(&self, entry_index: u64, checkpoint_tree_size: u64, trust: &TrustConfig) -> Result<String, String> {
        if trust.revocation_url.is_empty() {
            return Ok("skipped — no revocation_url in trust config (fail-open)".into());
        }

        const STALE_THRESHOLD: u64 = 32; // 2 × BATCH_SIZE

        // Check cache (and staleness).
        let cached_opt = {
            let cache = self.revoc_cache.lock().unwrap();
            cache.get(&trust.origin).map(|c| (c.tree_size, c.cascade.query(entry_index)))
        };

        // Attempt to use cache if not stale.
        if let Some((tree_size, _)) = cached_opt {
            if checkpoint_tree_size <= tree_size ||
               checkpoint_tree_size - tree_size <= STALE_THRESHOLD
            {
                // Cache is fresh — use it.
                let revoked = cached_opt.unwrap().1;
                return if revoked {
                    Err(format!("entry_index={entry_index} is revoked"))
                } else {
                    Ok(format!("entry_index={entry_index} not revoked (cascade checked, artifact tree_size={tree_size})"))
                };
            }
        }

        // Cache miss or stale — fetch.
        let artifact = self.fetch_revocation_artifact(trust).await
            .map_err(|e| format!("no revocation artifact (fail-closed): {e}"))?;

        let result = if artifact.cascade.query(entry_index) {
            Err(format!("entry_index={entry_index} is revoked"))
        } else {
            Ok(format!("entry_index={entry_index} not revoked (cascade checked, artifact tree_size={})", artifact.tree_size))
        };

        // Coverage check.
        if artifact.tree_size <= entry_index {
            return Err(format!(
                "entry_index={entry_index} not covered by artifact (tree_size={}) — fail-closed",
                artifact.tree_size
            ));
        }

        self.revoc_cache.lock().unwrap().insert(trust.origin.clone(), artifact);
        result
    }

    /// Fetch and parse the revocation artifact from revocation_url.
    async fn fetch_revocation_artifact(&self, trust: &TrustConfig) -> Result<CachedRevocation> {
        let url = &trust.revocation_url;
        // Use injected provider if available (tests bypass HTTP this way).
        if let Some(ref provider) = self.revocation_provider {
            let raw = provider(url)?;
            return self.parse_revocation_artifact(&raw, trust);
        }
        let raw = {
            #[cfg(feature = "goodkey")]
            {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?;
                let bytes = client.get(url).send().await
                    .map_err(|e| anyhow!("GET {url}: {e}"))?.bytes().await
                    .map_err(|e| anyhow!("read: {e}"))?;
                if bytes.len() > 64 * 1024 {
                    return Err(anyhow!("revocation artifact too large ({} bytes)", bytes.len()));
                }
                String::from_utf8(bytes.to_vec())?
            }
            #[cfg(not(feature = "goodkey"))]
            { return Err(anyhow!("HTTP not available without 'goodkey' feature")); }
        };
        self.parse_revocation_artifact(&raw, trust)
    }

    /// Parse and verify a revocation artifact string.
    fn parse_revocation_artifact(&self, text: &str, trust: &TrustConfig) -> Result<CachedRevocation> {
        let (body_part, sig_part) = text.split_once("\n\n")
            .ok_or_else(|| anyhow!("revocation artifact: missing blank line"))?;
        let body = format!("{body_part}\n");
        let lines: Vec<&str> = body_part.splitn(4, '\n').collect();
        if lines.len() != 4 {
            return Err(anyhow!("revocation artifact: expected 4 body lines, got {}", lines.len()));
        }
        let (origin, tree_size_str, artifact_type, casc_b64) =
            (lines[0], lines[1], lines[2], lines[3]);

        if origin != trust.origin {
            return Err(anyhow!("revocation artifact: origin mismatch"));
        }
        if artifact_type != "mta-qr-revocation-v1" {
            return Err(anyhow!("revocation artifact: unknown type {artifact_type:?}"));
        }
        let tree_size: u64 = tree_size_str.parse()
            .map_err(|_| anyhow!("revocation artifact: invalid tree_size"))?;
        if tree_size == 0 {
            return Err(anyhow!("revocation artifact: tree_size=0"));
        }

        let casc_bytes = B64.decode(casc_b64)
            .map_err(|e| anyhow!("revocation artifact: base64: {e}"))?;

        // Signature verification — algorithm binding per SPEC.md.
        let body_bytes = body.as_bytes();
        let key_prefix = format!("— {} ", trust.issuer_key_name);
        let mut sig_ok = false;
        for line in sig_part.lines() {
            if !line.starts_with(&key_prefix) { continue; }
            if let Some(raw) = last_field_base64(line) {
                if raw.len() >= 4 {
                    let sig = &raw[4..]; // strip key hash
                    if verify(trust.sig_alg, body_bytes, sig, &trust.issuer_pub_key) {
                        sig_ok = true;
                        break;
                    }
                }
            }
        }
        if !sig_ok {
            return Err(anyhow!("revocation artifact: signature verification failed"));
        }

        let cascade = crate::cascade::Cascade::decode(&casc_bytes)
            .map_err(|e| anyhow!("revocation artifact: cascade decode: {e}"))?;

        Ok(CachedRevocation { cascade, tree_size })
    }
}

// --- payload decoding ---

/// A witness cosignature embedded in a Mode 0 payload.
#[derive(Debug, Clone)]
pub(crate) struct WitnessCosig {
    pub(crate) key_id:    [u8; 4],
    pub(crate) timestamp: u64,
    pub(crate) signature: [u8; 64],
}

pub(crate) struct DecodedPayload {
    pub(crate) mode:         u8,
    pub(crate) sig_alg:      u8,
    pub(crate) origin_id:    u64,
    pub(crate) tree_size:    u64,
    pub(crate) entry_index:  u64,
    pub(crate) origin:       Option<String>,
    pub(crate) proof_hashes: Vec<Vec<u8>>,
    pub(crate) inner_count:  u8,
    pub(crate) tbs:          Vec<u8>,
    // Mode 0 only — embedded checkpoint fields.
    pub(crate) root_hash:    Option<[u8; 32]>,
    pub(crate) issuer_sig:   Option<Vec<u8>>,
    pub(crate) cosigs:       Vec<WitnessCosig>,
}

pub(crate) fn decode_payload(data: &[u8]) -> Result<DecodedPayload> {
    let mut pos = 0;
    let read_byte = |pos: &mut usize| -> Result<u8> {
        if *pos >= data.len() { return Err(anyhow!("unexpected end at offset {pos}")); }
        let b = data[*pos]; *pos += 1; Ok(b)
    };
    let read_u16 = |pos: &mut usize| -> Result<u16> {
        if *pos + 2 > data.len() { return Err(anyhow!("need 2 bytes at {pos}")); }
        let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]); *pos += 2; Ok(v)
    };
    let read_u64 = |pos: &mut usize| -> Result<u64> {
        if *pos + 8 > data.len() { return Err(anyhow!("need 8 bytes at {pos}")); }
        let v = u64::from_be_bytes(data[*pos..*pos+8].try_into().unwrap()); *pos += 8; Ok(v)
    };
    let read_bytes = |pos: &mut usize, n: usize| -> Result<Vec<u8>> {
        if *pos + n > data.len() { return Err(anyhow!("need {n} bytes at {pos}")); }
        let v = data[*pos..*pos+n].to_vec(); *pos += n; Ok(v)
    };

    let version = read_byte(&mut pos)?;
    if version != 0x01 { return Err(anyhow!("unsupported version 0x{version:02x}")); }
    let flags       = read_byte(&mut pos)?;
    let mode        = flags & 0x03;
    let sig_alg     = (flags >> 2) & 0x07;
    let self_describ = (flags & 0x80) != 0;
    let origin_id   = read_u64(&mut pos)?;
    let tree_size   = read_u64(&mut pos)?;
    let entry_index = read_u64(&mut pos)?;

    let origin = if self_describ {
        let len = read_u16(&mut pos)? as usize;
        let bytes = read_bytes(&mut pos, len)?;
        Some(String::from_utf8(bytes)?)
    } else { None };

    let num_proof = read_byte(&mut pos)? as usize;
    const MAX_PROOF_HASHES: usize = 64;
    if num_proof > MAX_PROOF_HASHES {
        return Err(anyhow!("payload: proof_count {} exceeds maximum {}", num_proof, MAX_PROOF_HASHES));
    }
    let inner_count = read_byte(&mut pos)?;
    let proof_hashes: Result<Vec<Vec<u8>>> = (0..num_proof)
        .map(|_| read_bytes(&mut pos, 32))
        .collect();
    let proof_hashes = proof_hashes?;

    let tbs_len = read_u16(&mut pos)? as usize;
    let tbs     = read_bytes(&mut pos, tbs_len)?;

    // Mode 0: parse embedded checkpoint fields.
    let (root_hash, issuer_sig, cosigs) = if mode == 0 {
        let rh_bytes = read_bytes(&mut pos, 32)?;
        let mut rh = [0u8; 32]; rh.copy_from_slice(&rh_bytes);
        let sig_len = read_u16(&mut pos)? as usize;
        let isig    = read_bytes(&mut pos, sig_len)?;
        let cosig_count = read_byte(&mut pos)? as usize;
        let mut cosigs = Vec::with_capacity(cosig_count);
        for _ in 0..cosig_count {
            let kid_bytes = read_bytes(&mut pos, 4)?;
            let mut kid = [0u8; 4]; kid.copy_from_slice(&kid_bytes);
            let ts  = read_u64(&mut pos)?;
            let sig_bytes = read_bytes(&mut pos, 64)?;
            let mut sig = [0u8; 64]; sig.copy_from_slice(&sig_bytes);
            cosigs.push(WitnessCosig { key_id: kid, timestamp: ts, signature: sig });
        }
        (Some(rh), Some(isig), cosigs)
    } else {
        (None, None, vec![])
    };

    if pos != data.len() {
        return Err(anyhow!("payload: {} trailing bytes after TBS", data.len() - pos));
    }

    Ok(DecodedPayload { mode, sig_alg, origin_id, tree_size, entry_index, origin,
                        proof_hashes, inner_count, tbs, root_hash, issuer_sig, cosigs })
}

// --- CBOR TBS decoding ---

/// Convert a ciborium CBOR value to a serde_json::Value, preserving type information.
/// Supports the types used in MTA-QR TBS claims: Text, Integer, Bool, Float, Null, Array, Map.
fn cbor_to_json(v: &ciborium::Value) -> serde_json::Value {
    use ciborium::Value;
    match v {
        Value::Text(s)    => serde_json::Value::String(s.clone()),
        Value::Integer(n) => {
            if let Ok(i) = i64::try_from(*n) {
                serde_json::Value::Number(i.into())
            } else {
                serde_json::Value::String(format!("{}", i128::from(*n)))
            }
        }
        Value::Bool(b)    => serde_json::Value::Bool(*b),
        Value::Null       => serde_json::Value::Null,
        Value::Float(f)   => {
            serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(cbor_to_json).collect()),
        Value::Map(m)     => {
            let obj: serde_json::Map<String, serde_json::Value> = m.iter()
                .filter_map(|(k, v)| {
                    if let Value::Text(key) = k {
                        Some((key.clone(), cbor_to_json(v)))
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null, // Bytes, Tag — not used in TBS claims
    }
}

fn decode_tbs(cbor_bytes: &[u8]) -> Result<(u64, u64, u64, HashMap<String, serde_json::Value>)> {
    use ciborium::Value;
    let value: Value = ciborium::from_reader(cbor_bytes)
        .map_err(|e| anyhow!("CBOR decode: {e}"))?;

    let map = match value {
        Value::Map(m) => m,
        _ => return Err(anyhow!("expected CBOR map")),
    };

    let get = |key: u64| -> Option<&ciborium::Value> {
        map.iter().find(|(k, _)| matches!(k, Value::Integer(n) if i64::try_from(*n).ok() == Some(key as i64)))
            .map(|(_, v)| v)
    };

    let times = match get(2) {
        Some(Value::Array(a)) if a.len() >= 2 => a,
        _ => return Err(anyhow!("missing times field")),
    };
    let issued_at  = extract_u64(&times[0])?;
    let expires_at = extract_u64(&times[1])?;
    let schema_id  = match get(3) { Some(v) => extract_u64(v)?, _ => 0 };

    let claims = match get(4) {
        Some(Value::Map(m)) => m.iter().filter_map(|(k, v)| {
            if let Value::Text(key) = k {
                let json_val = cbor_to_json(v);
                Some((key.clone(), json_val))
            } else {
                None // non-string keys are not supported in the TBS schema
            }
        }).collect(),
        _ => HashMap::new(),
    };

    Ok((issued_at, expires_at, schema_id, claims))
}

fn extract_u64(v: &ciborium::Value) -> Result<u64> {
    match v {
        ciborium::Value::Integer(n) => {
            i64::try_from(*n)
                .map(|i| i as u64)
                .map_err(|_| anyhow!("integer out of range"))
        }
        _ => Err(anyhow!("expected integer")),
    }
}

fn last_field_base64(line: &str) -> Option<Vec<u8>> {
    let idx = line.rfind(' ')?;
    B64.decode(line[idx + 1..].trim()).ok()
}

/// Test-accessible wrapper for decode_payload.
#[cfg(test)]
pub(crate) fn decode_payload_pub(data: &[u8]) -> Result<DecodedPayload> {
    decode_payload(data)
}

/// Test-accessible wrapper for verify_inclusion (via issuer module).
#[cfg(test)]
pub(crate) fn verify_inclusion_pub(
    leaf_hash: &[u8], idx: usize, tree_size: usize,
    proof: &[Vec<u8>], expected_root: &[u8],
) -> anyhow::Result<()> {
    crate::issuer::verify_inclusion(leaf_hash, idx, tree_size, proof, expected_root)
}
