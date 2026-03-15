//! Trust configuration for MTA-QR verifiers.
//!
//! Loaded from a JSON file at startup. The format matches the issuer's
//! `/trust-config` endpoint response, so configs can be captured from a running
//! issuer and deployed to verifiers.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sha2::{Sha256, Digest};

/// A single trusted witness public key.
#[derive(Clone, Debug)]
pub struct WitnessEntry {
    pub name:   String,
    pub key_id: [u8; 4],
    pub pub_key: Vec<u8>,
}

/// Trust anchor for a single MTA-QR issuer.
#[derive(Clone, Debug)]
pub struct TrustConfig {
    pub origin:          String,
    pub origin_id:       u64,
    pub issuer_key_name: String,
    pub issuer_pub_key:  Vec<u8>,
    pub sig_alg:         u8,
    pub witness_quorum:  usize,
    pub witnesses:       Vec<WitnessEntry>,
    pub checkpoint_url:  String,
    pub revocation_url:  String,  // empty string if issuer omits revocation_url
    pub batch_size:      usize,   // from trust config; defaults to 16
}

// Raw JSON shape matching the issuer's /trust-config endpoint
#[derive(Deserialize)]
struct TrustConfigJSON {
    origin:             String,
    origin_id:          String,  // hex, 16 chars
    issuer_key_name:    String,
    issuer_pub_key_hex: String,
    sig_alg:            u8,
    witness_quorum:     usize,
    checkpoint_url:     String,
    #[serde(default)]
    revocation_url:     String,
    #[serde(default)]
    batch_size:         Option<usize>,
    witnesses:          Vec<WitnessJSON>,
}

#[derive(Deserialize)]
struct WitnessJSON {
    name:        String,
    key_id_hex:  String,
    pub_key_hex: String,
}

impl TrustConfig {
    /// Load a trust config from a JSON file.
    pub async fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let data = tokio::fs::read(path.as_ref()).await
            .with_context(|| format!("reading trust config {:?}", path.as_ref()))?;
        Self::parse(&data)
    }

    /// Parse a trust config from JSON bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let raw: TrustConfigJSON = serde_json::from_slice(data)
            .context("parsing trust config JSON")?;
        Self::from_json(raw)
    }

    /// Parse a trust config from a JSON string.
    pub fn parse_str(s: &str) -> Result<Self> {
        Self::parse(s.as_bytes())
    }

    fn from_json(raw: TrustConfigJSON) -> Result<Self> {
        let origin_id = u64::from_str_radix(&raw.origin_id, 16)
            .with_context(|| format!("parsing origin_id {:?}", raw.origin_id))?;

        let issuer_pub_key = hex::decode(&raw.issuer_pub_key_hex)
            .context("decoding issuer_pub_key_hex")?;

        let witnesses = raw.witnesses.into_iter().enumerate().map(|(i, w)| {
            let kid = hex::decode(&w.key_id_hex)
                .with_context(|| format!("witness[{i}] key_id_hex"))?;
            let kid: [u8; 4] = kid.try_into()
                .map_err(|_| anyhow!("witness[{i}] key_id must be 4 bytes"))?;
            let pub_key = hex::decode(&w.pub_key_hex)
                .with_context(|| format!("witness[{i}] pub_key_hex"))?;
            Ok(WitnessEntry { name: w.name, key_id: kid, pub_key })
        }).collect::<Result<Vec<_>>>()?;

        if raw.witness_quorum < 1 {
            return Err(anyhow!(
                "trust config: witness_quorum must be >= 1, got {}", raw.witness_quorum
            ));
        }
        if raw.witness_quorum > witnesses.len() {
            return Err(anyhow!(
                "trust config: witness_quorum ({}) exceeds witness count ({})",
                raw.witness_quorum, witnesses.len()
            ));
        }
        let batch_size = raw.batch_size.unwrap_or(0);
        let batch_size = if batch_size > 0 { batch_size } else { 16 };
        Ok(Self {
            origin: raw.origin,
            origin_id,
            issuer_key_name: raw.issuer_key_name,
            issuer_pub_key,
            sig_alg: raw.sig_alg,
            witness_quorum: raw.witness_quorum,
            witnesses,
            checkpoint_url: raw.checkpoint_url,
            revocation_url: raw.revocation_url,
            batch_size,
        })
    }
}

/// Compute the origin_id for a given origin string.
/// First 8 bytes of SHA-256(origin) interpreted as big-endian u64.
pub fn compute_origin_id(origin: &str) -> u64 {
    let hash = Sha256::digest(origin.as_bytes());
    let mut id = 0u64;
    for &b in &hash[..8] {
        id = (id << 8) | b as u64;
    }
    id
}
