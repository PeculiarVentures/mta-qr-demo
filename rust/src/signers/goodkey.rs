//! GoodKeySigner — delegates signing to the GoodKey REST API.
//!
//! Signing goes through an async approval workflow:
//!   1. POST /key/{id}/operation                    — create sign operation
//!   2. GET  /key/{id}/operation/{opId}             — poll until status = "ready"
//!   3. PATCH /key/{id}/operation/{opId}/finalize   — submit hash, get signature
//!
//! Public key: GET /key/{id}/public → SPKI PEM
//!
//! Keys are referenced by UUID. Algorithm is specified by GoodKey name
//! (e.g. "ECDSA_P256_SHA256", "ED_25519", "ML_DSA_44").

use crate::signing::{BoxFuture, Signer, ALG_ED25519, ALG_ECDSA_P256, ALG_ML_DSA_44};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL}, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{Duration, Instant};

/// Configuration for a GoodKey-backed signer.
#[derive(Clone)]
pub struct GoodKeyConfig {
    /// GoodKey API root, e.g. `"https://api.goodkey.io"`.
    pub base_url:       String,
    /// UUID of the signing key in GoodKey.
    pub key_id:         String,
    /// Bearer token for API authentication.
    pub api_key:        String,
    /// GoodKey algorithm name, e.g. `"ECDSA_P256_SHA256"`, `"ED_25519"`, `"ML_DSA_44"`.
    pub algorithm_name: String,
    /// How long to poll for human approval. Default: 5 minutes.
    pub approval_timeout: Option<Duration>,
    /// Poll interval. Default: 3 seconds.
    pub poll_interval:    Option<Duration>,
}

#[derive(Deserialize)]
struct KeyOperationResponse {
    id:     String,
    status: String, // "pending" | "ready" | "invalid"
    error:  Option<String>,
}

#[derive(Deserialize)]
struct KeyOperationFinalizeResponse {
    data: String, // base64url encoded signature
}

#[derive(Serialize)]
struct CreateOperationRequest<'a> {
    r#type: &'a str,
    name:   &'a str,
}

#[derive(Serialize)]
struct FinalizeRequest<'a> {
    data: &'a str,
}

/// A signer backed by the GoodKey REST API.
pub struct GoodKeySigner {
    cfg:      GoodKeyConfig,
    client:   reqwest::Client,
    alg:      u8,
    key_name: String,
    pub_key:  Vec<u8>,
}

impl GoodKeySigner {
    /// Creates a GoodKeySigner, fetching public key metadata from GoodKey.
    pub async fn new(cfg: GoodKeyConfig) -> Result<Self> {
        let client = reqwest::Client::new();
        let alg    = alg_name_to_sig_alg(&cfg.algorithm_name)?;

        // Fetch public key — GoodKey returns SPKI PEM
        let pem = client
            .get(format!("{}/key/{}/public", cfg.base_url, cfg.key_id))
            .bearer_auth(&cfg.api_key)
            .send().await
            .map_err(|e| anyhow!("GoodKey: GET public key: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow!("GoodKey: GET public key: {e}"))?
            .text().await
            .map_err(|e| anyhow!("GoodKey: read public key: {e}"))?;

        let pub_key  = spki_pem_to_raw_pub_key(&pem, alg)?;
        let key_name = format!("goodkey-{}+{}", cfg.algorithm_name, B64.encode(&pub_key));

        Ok(Self { cfg, client, alg, key_name, pub_key })
    }
}

impl Signer for GoodKeySigner {
    fn alg(&self) -> u8        { self.alg }
    fn key_name(&self) -> &str { &self.key_name }

    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.pub_key.clone()) })
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let hash     = compute_hash(message, &self.cfg.algorithm_name);
            let hash_b64 = B64URL.encode(&hash);

            let timeout  = self.cfg.approval_timeout.unwrap_or(Duration::from_secs(300));
            let interval = self.cfg.poll_interval.unwrap_or(Duration::from_secs(3));

            // 1. Create sign operation
            let mut op: KeyOperationResponse = self.client
                .post(format!("{}/key/{}/operation", self.cfg.base_url, self.cfg.key_id))
                .bearer_auth(&self.cfg.api_key)
                .json(&CreateOperationRequest { r#type: "sign", name: &self.cfg.algorithm_name })
                .send().await.map_err(|e| anyhow!("GoodKey: create operation: {e}"))?
                .error_for_status().map_err(|e| anyhow!("GoodKey: create operation: {e}"))?
                .json().await.map_err(|e| anyhow!("GoodKey: parse create response: {e}"))?;

            // 2. Poll until ready
            let deadline = Instant::now() + timeout;
            while op.status == "pending" {
                if Instant::now() > deadline {
                    return Err(anyhow!("GoodKey: operation {} timed out", op.id));
                }
                tokio::time::sleep(interval).await;
                op = self.client
                    .get(format!("{}/key/{}/operation/{}", self.cfg.base_url, self.cfg.key_id, op.id))
                    .bearer_auth(&self.cfg.api_key)
                    .send().await.map_err(|e| anyhow!("GoodKey: poll: {e}"))?
                    .error_for_status().map_err(|e| anyhow!("GoodKey: poll: {e}"))?
                    .json().await.map_err(|e| anyhow!("GoodKey: parse poll response: {e}"))?;
            }

            if op.status != "ready" {
                return Err(anyhow!("GoodKey: operation {} ended with status {:?}: {}",
                    op.id, op.status, op.error.unwrap_or_default()));
            }

            // 3. Finalize
            let final_resp: KeyOperationFinalizeResponse = self.client
                .patch(format!("{}/key/{}/operation/{}/finalize",
                    self.cfg.base_url, self.cfg.key_id, op.id))
                .bearer_auth(&self.cfg.api_key)
                .json(&FinalizeRequest { data: &hash_b64 })
                .send().await.map_err(|e| anyhow!("GoodKey: finalize: {e}"))?
                .error_for_status().map_err(|e| anyhow!("GoodKey: finalize: {e}"))?
                .json().await.map_err(|e| anyhow!("GoodKey: parse finalize response: {e}"))?;

            B64URL.decode(&final_resp.data)
                .map_err(|e| anyhow!("GoodKey: decode signature: {e}"))
        })
    }
}

fn alg_name_to_sig_alg(name: &str) -> Result<u8> {
    let upper = name.to_uppercase();
    if upper.contains("ED_25519") || upper == "ED25519" { return Ok(ALG_ED25519); }
    if upper.contains("ECDSA_P256")                     { return Ok(ALG_ECDSA_P256); }
    if upper.contains("ML_DSA_44") || upper.contains("MLDSA44") { return Ok(ALG_ML_DSA_44); }
    Err(anyhow!("GoodKey: cannot map algorithm {name:?} to a known MTA-QR sig_alg"))
}

fn compute_hash(message: &[u8], alg_name: &str) -> Vec<u8> {
    let upper = alg_name.to_uppercase();
    if upper.contains("SHA256") { return Sha256::digest(message).to_vec(); }
    if upper.contains("SHA384") { return sha2::Sha384::digest(message).to_vec(); }
    if upper.contains("SHA512") { return sha2::Sha512::digest(message).to_vec(); }
    // Ed25519, ML-DSA: raw message
    message.to_vec()
}

fn spki_pem_to_raw_pub_key(pem: &str, alg: u8) -> Result<Vec<u8>> {
    // Strip PEM headers and decode base64
    let b64: String = pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = B64.decode(b64.trim())
        .map_err(|e| anyhow!("GoodKey: decode SPKI PEM: {e}"))?;

    // Extract raw key from the tail of the SPKI DER
    match alg {
        ALG_ED25519    => {
            if der.len() < 32 { return Err(anyhow!("SPKI too short for Ed25519")); }
            Ok(der[der.len()-32..].to_vec())
        }
        ALG_ECDSA_P256 => {
            if der.len() < 65 { return Err(anyhow!("SPKI too short for P-256")); }
            Ok(der[der.len()-65..].to_vec())
        }
        ALG_ML_DSA_44  => {
            if der.len() < 1312 { return Err(anyhow!("SPKI too short for ML-DSA-44")); }
            Ok(der[der.len()-1312..].to_vec())
        }
        _ => Err(anyhow!("unsupported alg {alg}")),
    }
}
