//! MTA-QR Issuer.
//!
//! Maintains an in-memory transparency log, issues signed QR code payloads,
//! and publishes cosigned checkpoints. All signing is delegated to the injected
//! [`Signer`] — the Issuer never holds private key material.

use crate::signing::{Signer, ALG_ED25519};
use subtle::ConstantTimeEq;

/// Constant-time byte slice equality. Prevents timing side-channels
/// when comparing Merkle roots or other security-relevant values.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
use crate::trust::compute_origin_id;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use ed25519_dalek::{SigningKey, Signer as DalekSigner};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for an Issuer.
#[derive(Clone, Default)]
pub struct IssuerConfig {
    /// Log origin string. Must be globally unique per (key, algorithm) pair.
    pub origin: String,
    /// Schema ID included in every issued assertion.
    pub schema_id: u64,
    /// Payload mode.
    ///   1 = Mode 1 (default): inclusion proof embedded at issuance time.
    ///   2 = Mode 2: no proof embedded. A production scanner fetches proof
    ///       tiles from a tile server at scan time. WARNING: this SDK's
    ///       Verifier does NOT perform that fetch — it validates everything
    ///       except inclusion. Use Mode 1 unless you implement tile fetching.
    pub mode: Option<u8>,
    /// Batch size for the tiled Merkle tree. Defaults to 16.
    pub batch_size: Option<usize>,
    /// Number of ephemeral witness cosignatures. Defaults to 2.
    pub witness_count: Option<usize>,
}

/// Result of a successful issue call.
#[derive(Debug, Clone)]
pub struct IssuedQR {
    pub entry_index:      u64,
    pub tree_size:        u64,
    /// Raw binary payload — encode this into a QR code.
    pub payload:          Vec<u8>,
    /// Base64url (no padding) encoding of the payload.
    pub payload_base64url: String,
}

const ENTRY_TYPE_NULL: u8 = 0x00;
const ENTRY_TYPE_DATA: u8 = 0x01;
const MODE_CACHED:     u8 = 1;
const MODE_ONLINE:     u8 = 2;

struct WitnessKey {
    name:    String,
    key_id:  [u8; 4],
    pub_key: Vec<u8>,
    signing: SigningKey,
}

struct LogEntry {
    tbs:        Vec<u8>,
    entry_hash: Vec<u8>,
}

struct Batch {
    entries: Vec<LogEntry>,
    root:    Vec<u8>,
}

struct SignedCheckpoint {
    tree_size:  u64,
    root_hash:  Vec<u8>,
    body:       Vec<u8>,
    issuer_sig: Vec<u8>,
    cosigs:     Vec<(Vec<u8>, u64, Vec<u8>)>, // (key_id, timestamp, sig)
}

struct State {
    issuer_pub:    Vec<u8>,
    origin_id:     u64,
    witnesses:     Vec<WitnessKey>,
    batches:       Vec<Batch>,
    current_batch: Vec<LogEntry>,
    latest_ckpt:   Option<SignedCheckpoint>,
}

/// The MTA-QR issuer.
pub struct Issuer {
    cfg:    IssuerConfig,
    signer: Arc<dyn Signer>,
    state:  Mutex<State>,
    batch_size: usize,
}

impl Issuer {
    pub fn new(cfg: IssuerConfig, signer: impl Signer + 'static) -> Self {
        let batch_size = cfg.batch_size.unwrap_or(16);
        Self {
            cfg,
            signer: Arc::new(signer),
            state: Mutex::new(State {
                issuer_pub:    vec![],
                origin_id:     0,
                witnesses:     vec![],
                batches:       vec![],
                current_batch: vec![],
                latest_ckpt:   None,
            }),
            batch_size,
        }
    }

    /// Initialize the issuer. Must be called before [`issue`](Self::issue).
    pub async fn init(&self) -> Result<()> {
        let pub_key = self.signer.public_key_bytes().await?;
        let origin_id = compute_origin_id(&self.cfg.origin);
        let witness_count = self.cfg.witness_count.unwrap_or(2);

        let witnesses = (0..witness_count).map(|i| {
            let seed: [u8; 32] = rand_seed();
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key().to_bytes().to_vec();
            let name = format!("witness-{i}");
            let key_id = witness_key_id(&name, &pk);
            WitnessKey { name, key_id, pub_key: pk, signing: sk }
        }).collect();

        let mut state = self.state.lock().await;
        state.issuer_pub = pub_key;
        state.origin_id  = origin_id;
        state.witnesses  = witnesses;

        // Genesis null_entry
        let null_tbs = vec![ENTRY_TYPE_NULL];
        append_entry_locked(&mut state, null_tbs, self.batch_size);

        drop(state);
        self.publish_checkpoint().await
    }

    /// Issue a QR code payload for a set of claims.
    pub async fn issue(
        &self,
        claims: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        ttl: Duration,
    ) -> Result<IssuedQR> {
        let now    = unix_now();
        let expiry = now + ttl.as_secs();
        let claims: Vec<(String, String)> = claims.into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let tbs = encode_tbs(now, expiry, self.cfg.schema_id, &claims)?;

        let idx = {
            let mut state = self.state.lock().await;
            if state.latest_ckpt.is_none() {
                return Err(anyhow!("call init() before issue()"));
            }
            append_entry_locked(&mut state, tbs.clone(), self.batch_size)
        };

        self.publish_checkpoint().await?;

        let state = self.state.lock().await;
        let ckpt  = state.latest_ckpt.as_ref().unwrap();
        let mode    = self.cfg.mode.unwrap_or(1).clamp(1, 2);
        let payload = build_payload(&state, idx, &tbs, ckpt, &self.cfg.origin, self.batch_size, self.signer.alg(), mode)?;
        let payload_base64url = B64URL.encode(&payload);

        Ok(IssuedQR {
            entry_index: idx,
            tree_size:   ckpt.tree_size,
            payload,
            payload_base64url,
        })
    }

    /// Returns the trust config as a JSON string for verifiers.
    pub async fn trust_config_json(&self, checkpoint_url: &str) -> Result<String> {
        let state = self.state.lock().await;
        if state.latest_ckpt.is_none() {
            return Err(anyhow!("call init() before trust_config_json()"));
        }
        let witnesses: Vec<serde_json::Value> = state.witnesses.iter().map(|w| {
            serde_json::json!({
                "name":        w.name,
                "key_id_hex":  hex::encode(w.key_id),
                "pub_key_hex": hex::encode(&w.pub_key),
            })
        }).collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "origin":             self.cfg.origin,
            "origin_id":          format!("{:016x}", state.origin_id),
            "issuer_key_name":    self.signer.key_name(),
            "issuer_pub_key_hex": hex::encode(&state.issuer_pub),
            "sig_alg":            self.signer.alg(),
            "witness_quorum":     state.witnesses.len(),
            "checkpoint_url":     checkpoint_url,
            "batch_size":         self.batch_size,
            "witnesses":          witnesses,
        }))?)
    }

    /// Returns the current signed checkpoint note (tlog-checkpoint signed-note format).
    pub async fn checkpoint_note(&self) -> Result<String> {
        let state = self.state.lock().await;
        let ckpt  = state.latest_ckpt.as_ref()
            .ok_or_else(|| anyhow!("not initialized"))?;

        let mut note = String::from_utf8(ckpt.body.clone())? + "\n";
        // Per c2sp.org/signed-note: sig payload = 4-byte key_hash || raw_sig
        let issuer_key_id = witness_key_id(self.signer.key_name(),
            &state.issuer_pub);
        let mut issuer_payload = Vec::with_capacity(4 + ckpt.issuer_sig.len());
        issuer_payload.extend_from_slice(&issuer_key_id);
        issuer_payload.extend_from_slice(&ckpt.issuer_sig);
        note += &format!("— {} {}\n",
            self.signer.key_name(),
            B64.encode(&issuer_payload));

        for (i, w) in state.witnesses.iter().enumerate() {
            let (_, ts, sig) = &ckpt.cosigs[i];
            // Per c2sp.org/signed-note + tlog-cosignature:
            //   4-byte key_hash || 8-byte timestamp || 64-byte Ed25519 sig = 76 bytes
            let mut payload = vec![0u8; 76];
            payload[..4].copy_from_slice(&w.key_id);
            payload[4..12].copy_from_slice(&ts.to_be_bytes());
            payload[12..].copy_from_slice(sig);
            note += &format!("— {} {}\n", w.name, B64.encode(&payload));
        }
        Ok(note)
    }

    async fn publish_checkpoint(&self) -> Result<()> {
        let (origin_id, tree_size, parent_root) = {
            let state = self.state.lock().await;
            let roots = batch_roots(&state);
            let root  = merkle_root(&roots)?;
            (state.origin_id, total_entries(&state), root)
        };

        let body      = checkpoint_body(&self.cfg.origin, tree_size, &parent_root);
        let issuer_sig = self.signer.sign(&body).await?;
        let ts        = unix_now();

        let cosigs: Vec<(Vec<u8>, u64, Vec<u8>)> = {
            let state = self.state.lock().await;
            state.witnesses.iter().map(|w| {
                let msg = cosignature_message(&body, ts);
                let sig = w.signing.sign(&msg).to_bytes().to_vec();
                (w.key_id.to_vec(), ts, sig)
            }).collect()
        };

        let mut state = self.state.lock().await;
        state.latest_ckpt = Some(SignedCheckpoint {
            tree_size, root_hash: parent_root, body, issuer_sig, cosigs,
        });
        Ok(())
    }
}

// --- protocol helpers ---

fn append_entry_locked(state: &mut State, tbs: Vec<u8>, batch_size: usize) -> u64 {
    let idx = total_entries(state);
    let entry_hash = hash_leaf(&tbs);
    state.current_batch.push(LogEntry { tbs, entry_hash });
    if state.current_batch.len() >= batch_size {
        let hashes: Vec<_> = state.current_batch.iter().map(|e| e.entry_hash.clone()).collect();
        let root = merkle_root(&hashes).unwrap();
        let entries = std::mem::take(&mut state.current_batch);
        state.batches.push(Batch { entries, root });
    }
    idx
}

fn total_entries(state: &State) -> u64 {
    state.batches.iter().map(|b| b.entries.len() as u64).sum::<u64>()
        + state.current_batch.len() as u64
}

fn batch_roots(state: &State) -> Vec<Vec<u8>> {
    let mut roots: Vec<_> = state.batches.iter().map(|b| b.root.clone()).collect();
    if !state.current_batch.is_empty() {
        let hashes: Vec<_> = state.current_batch.iter().map(|e| e.entry_hash.clone()).collect();
        roots.push(merkle_root(&hashes).unwrap());
    }
    roots
}

fn build_payload(
    state: &State,
    global_idx: u64,
    tbs: &[u8],
    ckpt: &SignedCheckpoint,
    origin: &str,
    batch_size: usize,
    sig_alg: u8,
    mode: u8,
) -> Result<Vec<u8>> {
    // Mode 2: no proof embedded.
    if mode == MODE_ONLINE {
        return Ok(encode_payload(
            global_idx, ckpt.tree_size, state.origin_id,
            origin, &[], 0, tbs, sig_alg, MODE_ONLINE,
        ));
    }

    // Mode 1: embed two-phase tiled Merkle proof.
    let batch_idx = global_idx as usize / batch_size;
    let inner_idx = global_idx as usize % batch_size;

    let (batch_hashes, batch_sz) = if batch_idx < state.batches.len() {
        let b = &state.batches[batch_idx];
        let h: Vec<_> = b.entries.iter().map(|e| e.entry_hash.clone()).collect();
        let sz = b.entries.len();
        (h, sz)
    } else {
        let h: Vec<_> = state.current_batch.iter().map(|e| e.entry_hash.clone()).collect();
        let sz = state.current_batch.len();
        (h, sz)
    };

    let entry_hash  = hash_leaf(tbs);
    let inner_proof = inclusion_proof(&batch_hashes, inner_idx, batch_sz)?;
    let all_roots   = batch_roots(state);
    let outer_proof = inclusion_proof(&all_roots, batch_idx, all_roots.len())?;

    let proof_hashes: Vec<_> = inner_proof.iter().chain(outer_proof.iter()).cloned().collect();
    let inner_count = inner_proof.len() as u8;

    let _ = entry_hash;
    Ok(encode_payload(
        global_idx, ckpt.tree_size, state.origin_id,
        origin, &proof_hashes, inner_count, tbs, sig_alg, MODE_CACHED,
    ))
}

// --- Merkle tree ---

pub(crate) fn hash_leaf(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().to_vec()
}

fn hash_node(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}

pub(crate) fn merkle_root(leaves: &[Vec<u8>]) -> Result<Vec<u8>> {
    if leaves.is_empty() { return Err(anyhow!("merkle: empty")); }
    Ok(reduce_level(leaves.to_vec()))
}

fn reduce_level(nodes: Vec<Vec<u8>>) -> Vec<u8> {
    if nodes.len() == 1 { return nodes.into_iter().next().unwrap(); }
    let mut next = vec![];
    let mut i = 0;
    while i + 1 < nodes.len() {
        next.push(hash_node(&nodes[i], &nodes[i + 1]));
        i += 2;
    }
    if nodes.len() % 2 == 1 { next.push(nodes.last().unwrap().clone()); }
    reduce_level(next)
}

pub(crate) fn inclusion_proof(leaves: &[Vec<u8>], idx: usize, tree_size: usize) -> Result<Vec<Vec<u8>>> {
    if tree_size == 0 || idx >= tree_size {
        return Err(anyhow!("merkle: invalid index {idx}"));
    }
    let mut proof = vec![];
    let mut current = leaves.to_vec();
    let mut idx = idx;
    while current.len() > 1 {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(if sib < current.len() { current[sib].clone() } else { current[idx].clone() });
        let mut next = vec![];
        let mut i = 0;
        while i + 1 < current.len() {
            next.push(hash_node(&current[i], &current[i + 1]));
            i += 2;
        }
        if current.len() % 2 == 1 { next.push(current.last().unwrap().clone()); }
        idx /= 2;
        current = next;
    }
    Ok(proof)
}

pub(crate) fn compute_root_from_proof(
    start: &[u8], idx: usize, tree_size: usize, proof: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if tree_size == 0 || idx >= tree_size {
        return Err(anyhow!("merkle: invalid index"));
    }
    let mut node = start.to_vec();
    let mut idx  = idx;
    let mut size = tree_size;
    for sib in proof {
        if idx % 2 == 0 {
            if idx + 1 == size && size % 2 == 1 { idx /= 2; size = (size + 1) / 2; continue; }
            node = hash_node(&node, sib);
        } else {
            node = hash_node(sib, &node);
        }
        idx  /= 2;
        size  = (size + 1) / 2;
    }
    Ok(node)
}

pub(crate) fn verify_inclusion(
    leaf_hash: &[u8], idx: usize, tree_size: usize,
    proof: &[Vec<u8>], expected_root: &[u8],
) -> Result<()> {
    let computed = compute_root_from_proof(leaf_hash, idx, tree_size, proof)?;
    // constant_time_eq prevents timing side-channels on the root hash comparison.
    if !constant_time_eq(&computed, expected_root) {
        return Err(anyhow!("merkle: root mismatch"));
    }
    Ok(())
}

// --- Checkpoint ---

pub(crate) fn checkpoint_body(origin: &str, tree_size: u64, root_hash: &[u8]) -> Vec<u8> {
    let b64 = B64.encode(root_hash);
    format!("{origin}\n{tree_size}\n{b64}\n").into_bytes()
}

pub(crate) fn cosignature_message(body: &[u8], timestamp: u64) -> Vec<u8> {
    let header = format!("cosignature/v1\ntime {timestamp}\n");
    let mut msg = header.into_bytes();
    msg.extend_from_slice(body);
    msg
}

fn witness_key_id(name: &str, pub_key: &[u8]) -> [u8; 4] {
    // Per c2sp.org/signed-note Ed25519:
    //   key_id = SHA-256(name || 0x0A || 0x01 || raw_pubkey)[0:4]
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(&[0x0a, 0x01]); // newline + Ed25519 type byte
    h.update(pub_key);
    h.finalize()[..4].try_into().unwrap()
}

// --- CBOR TBS encoding ---

fn encode_tbs(
    issued_at: u64, expires_at: u64, schema_id: u64,
    claims: &[(String, String)],
) -> Result<Vec<u8>> {
    // Minimal canonical CBOR: map{2:[times], 3:schemaId, 4:map{claims}}
    // Use ciborium for canonical encoding
    use ciborium::Value;

    // Sort claims alphabetically by key for canonical CBOR — must match TS/Go.
    let mut sorted_claims: Vec<&(String, String)> = claims.iter().collect();
    sorted_claims.sort_by(|a, b| a.0.cmp(&b.0));
    let claims_map: Vec<(Value, Value)> = sorted_claims.iter()
        .map(|(k, v)| (Value::Text((*k).clone()), Value::Text((*v).clone())))
        .collect();

    let entry = Value::Map(vec![
        (Value::Integer(2u64.into()), Value::Array(vec![
            Value::Integer(issued_at.into()),
            Value::Integer(expires_at.into()),
        ])),
        (Value::Integer(3u64.into()), Value::Integer(schema_id.into())),
        (Value::Integer(4u64.into()), Value::Map(claims_map)),
    ]);

    let mut cbor = vec![];
    ciborium::into_writer(&entry, &mut cbor)
        .map_err(|e| anyhow!("CBOR encode: {e}"))?;

    let mut tbs = vec![ENTRY_TYPE_DATA];
    tbs.extend_from_slice(&cbor);
    Ok(tbs)
}

// --- Payload binary encoding ---

fn encode_payload(
    entry_idx: u64, tree_size: u64, origin_id: u64,
    origin: &str, proof_hashes: &[Vec<u8>], inner_count: u8,
    tbs: &[u8], sig_alg: u8, mode: u8,
) -> Vec<u8> {
    let origin_bytes = origin.as_bytes();
    let mut buf = vec![];
    buf.push(0x01u8); // version
    // flags byte: [7]=self-describing, [5]=dual_sig(0), [4:2]=sig_alg, [1:0]=mode
    let flags: u8 = 0x80 | ((sig_alg & 0x07) << 2) | (mode & 0x03);
    buf.push(flags);
    buf.extend_from_slice(&origin_id.to_be_bytes());
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(&entry_idx.to_be_bytes());
    let origin_len = origin_bytes.len() as u16;
    buf.extend_from_slice(&origin_len.to_be_bytes());
    buf.extend_from_slice(origin_bytes);
    buf.push(proof_hashes.len() as u8);
    buf.push(inner_count);
    for h in proof_hashes { buf.extend_from_slice(h); }
    buf.extend_from_slice(&(tbs.len() as u16).to_be_bytes());
    buf.extend_from_slice(tbs);
    buf
}

// --- utils ---

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn rand_seed() -> [u8; 32] {
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    seed
}
