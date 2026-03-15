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

const BATCH_SIZE: usize = 16;
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
    pub claims:      HashMap<String, String>,
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
pub type NoteProvider = Box<dyn Fn(&str) -> Result<String> + Send + Sync>;

/// The MTA-QR verifier.
pub struct Verifier {
    trust:         TrustConfig,
    note_provider: Option<NoteProvider>,
    // Bounded cache: VecDeque tracks insertion order for eviction.
    // Capped at MAX_CACHE_ENTRIES to prevent memory exhaustion.
    cache: Mutex<(VecDeque<String>, HashMap<String, Vec<u8>>)>,
}

impl Verifier {
    /// Create a Verifier from a trust config.
    pub fn new(trust: TrustConfig) -> Self {
        Self { trust, note_provider: None, cache: Mutex::new((VecDeque::new(), HashMap::new())) }
    }

    /// Create a Verifier that fetches checkpoint notes via `provider`.
    /// Used in tests to avoid HTTP.
    pub fn with_note_provider(trust: TrustConfig, provider: NoteProvider) -> Self {
        Self { trust, note_provider: Some(provider), cache: Mutex::new((VecDeque::new(), HashMap::new())) }
    }

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

        // 3. Origin ID
        if p.origin_id != self.trust.origin_id {
            fail!("origin id", format!("payload origin_id 0x{:016x} does not match trust config", p.origin_id));
        }
        add!(true, "origin id", format!("matches trust config: {:?}", self.trust.origin));

        // 4. Self-describing origin consistency
        if let Some(ref env_origin) = p.origin {
            if env_origin != &self.trust.origin {
                fail!("origin consistency", format!("envelope {:?} != trust config {:?}", env_origin, self.trust.origin));
            }
            add!(true, "origin consistency", "envelope matches trust config");
        }

        // 5. Algorithm binding
        if p.sig_alg != self.trust.sig_alg {
            fail!("algorithm binding", format!("payload sig_alg={} but trust config requires {}", p.sig_alg, self.trust.sig_alg));
        }
        add!(true, "algorithm binding", format!("sig_alg={} matches trust config", p.sig_alg));

        // 6. Checkpoint resolution
        let cache_key = format!("{}:{}", self.trust.origin, p.tree_size);
        let cached_root = self.cache.lock().unwrap().1.get(&cache_key).cloned();

        let root_hash = if let Some(r) = cached_root {
            add!(true, "checkpoint", format!("cache hit · tree_size={}", p.tree_size));
            r
        } else {
            add!(false, "checkpoint", format!("cache miss · fetching {}", self.trust.checkpoint_url));
            match self.fetch_and_verify_checkpoint(p.tree_size).await {
                Ok((root, fetched_size)) => {
                    add!(true, "checkpoint fetch", format!(
                        "issuer sig ✓ · {}/{} witnesses ✓ · tree_size={}",
                        self.trust.witness_quorum, self.trust.witness_quorum, fetched_size));
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
            let inner_idx    = global_idx % BATCH_SIZE;
            let batch_idx    = global_idx / BATCH_SIZE;
            let num_batches  = (p.tree_size as usize + BATCH_SIZE - 1) / BATCH_SIZE;
            let batch_start  = batch_idx * BATCH_SIZE;
            let this_batch_sz = BATCH_SIZE.min(p.tree_size as usize - batch_start);

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

        // 11. Expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if expires_at + GRACE < now {
            fail!("expiry", format!("expired: expiry={expires_at} now={now}"));
        }
        add!(true, "expiry", format!("valid · {}s remaining", expires_at as i64 - now as i64));

        add!(true, "complete", format!(
            "all checks passed · entry_index={} · origin={:?}", p.entry_index, self.trust.origin));

        TraceResult {
            ok: Some(VerifyOk {
                mode:        p.mode,
                entry_index: p.entry_index,
                tree_size:   p.tree_size,
                origin:      self.trust.origin.clone(),
                schema_id,
                issued_at,
                expires_at,
                claims,
            }),
            fail: None,
            steps,
        }
    }

    async fn fetch_and_verify_checkpoint(&self, required_size: u64) -> Result<(Vec<u8>, u64)> {
        let note = if let Some(ref provider) = self.note_provider {
            provider(&self.trust.checkpoint_url)?
        } else {
            #[cfg(feature = "goodkey")]
            {
                let resp = reqwest::get(&self.trust.checkpoint_url).await
                    .map_err(|e| anyhow!("GET {}: {e}", self.trust.checkpoint_url))?;
                resp.text().await
                    .map_err(|e| anyhow!("read checkpoint: {e}"))?
            }
            #[cfg(not(feature = "goodkey"))]
            {
                return Err(anyhow!(
                    "no note provider and HTTP not available without 'goodkey' feature"
                ));
            }
        };
        self.verify_note(&note, required_size)
    }

    fn verify_note(&self, note: &str, required_size: u64) -> Result<(Vec<u8>, u64)> {
        let blank = note.find("\n\n")
            .ok_or_else(|| anyhow!("note missing blank-line separator"))?;
        let body: Vec<u8> = (note[..blank].to_string() + "\n").into_bytes();
        let rest = &note[blank + 2..];

        // Parse body
        let body_str = std::str::from_utf8(&body)?;
        let lines: Vec<&str> = body_str.trim_end_matches('\n').splitn(3, '\n').collect();
        if lines.len() != 3 { return Err(anyhow!("checkpoint body must have 3 lines")); }
        let note_origin  = lines[0];
        let tree_size: u64 = lines[1].parse()?;
        let root_hash    = B64.decode(lines[2])?;

        if note_origin != self.trust.origin {
            return Err(anyhow!("origin mismatch: {:?}", note_origin));
        }
        if tree_size < required_size {
            return Err(anyhow!("tree_size {tree_size} < required {required_size}"));
        }

        let sig_lines: Vec<&str> = rest.lines().filter(|l| !l.trim().is_empty()).collect();

        // Issuer sig — dispatch by key name, skip 4-byte key_hash prefix
        let mut issuer_ok = false;
        for line in &sig_lines {
            if !line.contains(&self.trust.issuer_key_name) { continue; }
            if let Some(raw) = last_field_base64(line) {
                if raw.len() < 4 { continue; }
                // Per c2sp.org/signed-note: first 4 bytes are key_hash; rest is sig.
                let raw_sig = &raw[4..];
                if verify(self.trust.sig_alg, &body, raw_sig, &self.trust.issuer_pub_key) {
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
                for w in &self.trust.witnesses {
                    if w.key_id != key_hash { continue; }
                    if verify(ALG_ED25519, &msg, wsig, &w.pub_key) {
                        verified.insert(w.name.clone());
                    }
                }
            }
        }
        if verified.len() < self.trust.witness_quorum {
            return Err(anyhow!("witness quorum not met: {}/{}", verified.len(), self.trust.witness_quorum));
        }

        Ok((root_hash, tree_size))
    }
}

// --- payload decoding ---

struct DecodedPayload {
    mode:         u8,
    sig_alg:      u8,
    origin_id:    u64,
    tree_size:    u64,
    entry_index:  u64,
    origin:       Option<String>,
    proof_hashes: Vec<Vec<u8>>,
    inner_count:  u8,
    tbs:          Vec<u8>,
}

fn decode_payload(data: &[u8]) -> Result<DecodedPayload> {
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

    let num_proof   = read_byte(&mut pos)? as usize;
    let inner_count = read_byte(&mut pos)?;
    let proof_hashes: Result<Vec<Vec<u8>>> = (0..num_proof)
        .map(|_| read_bytes(&mut pos, 32))
        .collect();
    let proof_hashes = proof_hashes?;

    let tbs_len = read_u16(&mut pos)? as usize;
    let tbs     = read_bytes(&mut pos, tbs_len)?;

    if pos != data.len() {
        return Err(anyhow!("payload: {} trailing bytes after TBS", data.len() - pos));
    }

    Ok(DecodedPayload { mode, sig_alg, origin_id, tree_size, entry_index, origin, proof_hashes, inner_count, tbs })
}

// --- CBOR TBS decoding ---

fn decode_tbs(cbor_bytes: &[u8]) -> Result<(u64, u64, u64, HashMap<String, String>)> {
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
            match (k, v) {
                (Value::Text(k), Value::Text(v)) => Some((k.clone(), v.clone())),
                _ => None,
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
