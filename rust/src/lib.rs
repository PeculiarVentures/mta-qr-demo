//! MTA-QR SDK — Merkle Tree Assertions for Verifiable QR Codes.
//!
//! # Quick start (issuer)
//!
//! ```no_run
//! use mta_qr::{Issuer, IssuerConfig};
//! use mta_qr::signers::LocalSigner;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let signer = LocalSigner::ed25519(&[0u8; 32])?;
//!     let issuer = Issuer::new(
//!         IssuerConfig { origin: "example.com/log/v1".into(), schema_id: 1, ..Default::default() },
//!         signer,
//!     );
//!     issuer.init().await?;
//!     let qr = issuer.issue([("subject", "Alice")], Duration::from_secs(3600)).await?;
//!     println!("payload: {}", qr.payload_base64url);
//!     Ok(())
//! }
//! ```
//!
//! # Quick start (verifier)
//!
//! ```no_run
//! use mta_qr::{Verifier, TrustConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let trust = TrustConfig::load_file("trust.json").await?;
//!     let verifier = Verifier::new(trust);
//!     let payload_bytes = vec![0u8; 0]; // placeholder
//!     let ok = verifier.verify(&payload_bytes).await?;
//!     println!("{:?}", ok.claims);
//!     Ok(())
//! }
//! ```

pub mod signing;
pub mod signers;
pub mod trust;
pub mod issuer;
pub mod verifier;

// Re-export top-level types for convenience
pub use signing::Signer;
pub use trust::TrustConfig;
pub use issuer::{Issuer, IssuerConfig, IssuedQR};
pub use verifier::{Verifier, VerifyOk, VerifyFail, VerifyStep, TraceResult};

#[cfg(test)]
mod vector_tests {
    use std::path::PathBuf;
    use serde_json::Value;
    use crate::issuer::{hash_leaf, merkle_root, inclusion_proof, checkpoint_body};
    use crate::signing::verify::verify;
    use crate::signers::LocalSigner;

    fn repo_root() -> PathBuf {
        // File is at rust/src/lib.rs; repo root is two levels up.
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    fn load_vectors() -> serde_json::Map<String, Value> {
        let path = repo_root().join("test-vectors/vectors.json");
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let root: Value = serde_json::from_str(&data).unwrap();
        let vecs = root["vectors"].as_array().unwrap();
        let mut map = serde_json::Map::new();
        for v in vecs {
            map.insert(v["id"].as_str().unwrap().to_string(), v.clone());
        }
        map
    }

    fn hex(b: &[u8]) -> String { hex::encode(b) }
    fn from_hex(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }

    // --- checkpoint-body-v1 ---
    #[test]
    fn test_checkpoint_body() {
        let vs = load_vectors();
        let v = &vs["checkpoint-body-v1"];
        let origin    = v["input"]["origin"].as_str().unwrap();
        let tree_size = v["input"]["tree_size"].as_u64().unwrap();
        let root_hash = from_hex(v["input"]["root_hash_hex"].as_str().unwrap());
        let expected_hex = v["expected"]["checkpoint_body_hex"].as_str().unwrap();
        let expected_len = v["expected"]["byte_length"].as_u64().unwrap() as usize;

        let body = checkpoint_body(origin, tree_size, &root_hash);
        assert_eq!(body.len(), expected_len, "checkpoint body byte length");
        assert_eq!(hex(&body), expected_hex, "checkpoint body hex");
        assert_eq!(*body.last().unwrap(), b'\n', "body must end with \\n");
    }

    // --- null-entry-hash ---
    #[test]
    fn test_null_entry_hash() {
        let vs = load_vectors();
        let v = &vs["null-entry-hash"];
        let expected = v["expected"]["entry_hash_hex"].as_str().unwrap();

        let tbs = &[0x00u8];
        let got = hash_leaf(tbs);
        assert_eq!(hex(&got), expected, "null entry hash");
    }

    // --- data-assertion-cbor ---
    #[test]
    fn test_data_assertion_cbor() {
        let vs = load_vectors();
        let v = &vs["data-assertion-cbor"];
        let inp = &v["input"];

        // Build claims in the expected format (single string value)
        let claims_json = inp["claims"].as_object().unwrap();
        let mut claims: Vec<(String, String)> = claims_json.iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        claims.sort_by(|a, b| a.0.cmp(&b.0));

        // Use encode_tbs directly via the issuer module
        use crate::issuer::encode_tbs_pub;
        let tbs = encode_tbs_pub(
            inp["issuance_time"].as_u64().unwrap(),
            inp["expiry_time"].as_u64().unwrap(),
            inp["schema_id"].as_u64().unwrap(),
            &claims,
        ).unwrap();

        let expected_tbs = v["expected"]["tbs_hex"].as_str().unwrap();
        assert_eq!(hex(&tbs), expected_tbs, "TBS hex");

        let entry_hash = hash_leaf(&tbs);
        let expected_hash = v["expected"]["entry_hash_hex"].as_str().unwrap();
        assert_eq!(hex(&entry_hash), expected_hash, "entry hash");
    }

    // --- merkle-four-entry-tree ---
    #[test]
    fn test_merkle_four_entry_tree() {
        let vs = load_vectors();
        let v = &vs["merkle-four-entry-tree"];
        let leaves_input = v["input"]["leaves"].as_array().unwrap();

        let leaves: Vec<Vec<u8>> = leaves_input.iter()
            .map(|l| hash_leaf(&from_hex(l["data_hex"].as_str().unwrap())))
            .collect();

        // Check leaf hashes
        let expected_leaves = v["expected"]["leaf_hashes"].as_array().unwrap();
        for (i, (got, exp)) in leaves.iter().zip(expected_leaves).enumerate() {
            assert_eq!(hex(got), exp.as_str().unwrap(), "leaf[{i}]");
        }

        // Check internal nodes
        let exp_nodes = &v["expected"]["internal_nodes"];
        let h01 = crate::issuer::hash_node_pub(&leaves[0], &leaves[1]);
        let h23 = crate::issuer::hash_node_pub(&leaves[2], &leaves[3]);
        assert_eq!(hex(&h01), exp_nodes["H01"].as_str().unwrap(), "H01");
        assert_eq!(hex(&h23), exp_nodes["H23"].as_str().unwrap(), "H23");

        // Check root
        let root = merkle_root(&leaves).unwrap();
        assert_eq!(hex(&root), v["expected"]["root"].as_str().unwrap(), "root");

        // Check inclusion proof for index 2
        let ip = &v["expected"]["inclusion_proof_index2"];
        let proof = inclusion_proof(&leaves, 2, 4).unwrap();
        let exp_proof = ip["proof"].as_array().unwrap();
        assert_eq!(proof.len(), exp_proof.len(), "proof length");
        for (i, (got, exp)) in proof.iter().zip(exp_proof).enumerate() {
            assert_eq!(hex(got), exp.as_str().unwrap(), "proof[{i}]");
        }
    }

    // --- signing-ed25519 ---
    #[test]
    fn test_signing_ed25519() {
        let vs = load_vectors();
        let v = &vs["signing-ed25519"];
        let seed    = from_hex(v["input"]["private_seed_hex"].as_str().unwrap());
        let message = from_hex(v["input"]["message_hex"].as_str().unwrap());

        let signer = LocalSigner::ed25519(&seed).unwrap();
        let pub_key = tokio_test::block_on(signer.public_key_bytes()).unwrap();
        assert_eq!(hex(&pub_key), v["expected"]["public_key_hex"].as_str().unwrap(), "Ed25519 pubkey");

        let sig = tokio_test::block_on(signer.sign(&message)).unwrap();
        assert_eq!(hex(&sig), v["expected"]["signature_hex"].as_str().unwrap(), "Ed25519 sig deterministic");

        assert!(verify(6, &message, &sig, &pub_key), "Ed25519 verify");
    }

    // --- signing-ecdsa-p256 ---
    #[test]
    fn test_signing_ecdsa_p256() {
        let vs = load_vectors();
        let v = &vs["signing-ecdsa-p256"];
        let scalar  = from_hex(v["input"]["scalar_hex"].as_str().unwrap());
        let message = from_hex(v["input"]["message_hex"].as_str().unwrap());

        let signer = LocalSigner::ecdsa_p256(&scalar).unwrap();
        let pub_key = tokio_test::block_on(signer.public_key_bytes()).unwrap();
        assert_eq!(hex(&pub_key), v["expected"]["public_key_hex"].as_str().unwrap(), "ECDSA P-256 pubkey");

        // Verify pre-recorded Go reference signature
        let pre_sig = from_hex(v["input"]["pre_recorded_sig"].as_str().unwrap());
        assert!(verify(4, &message, &pre_sig, &pub_key), "ECDSA P-256 verify pre-recorded sig");

        // Round-trip: sign and verify
        let sig = tokio_test::block_on(signer.sign(&message)).unwrap();
        assert!(verify(4, &message, &sig, &pub_key), "ECDSA P-256 round-trip verify");
    }

    // --- signing-mldsa44 ---
    #[test]
    fn test_signing_mldsa44() {
        let vs = load_vectors();
        let v = &vs["signing-mldsa44"];
        let seed    = from_hex(v["input"]["seed_hex"].as_str().unwrap());
        let message = from_hex(v["input"]["message_hex"].as_str().unwrap());

        let signer = LocalSigner::ml_dsa_44(&seed).unwrap();
        let pub_key = tokio_test::block_on(signer.public_key_bytes()).unwrap();
        assert_eq!(hex(&pub_key), v["expected"]["public_key_hex"].as_str().unwrap(), "ML-DSA-44 pubkey");

        // Verify pre-recorded signature
        let pre_sig = from_hex(v["input"]["pre_recorded_sig"].as_str().unwrap());
        assert!(verify(1, &message, &pre_sig, &pub_key), "ML-DSA-44 verify pre-recorded sig");

        // Round-trip
        let sig = tokio_test::block_on(signer.sign(&message)).unwrap();
        assert!(verify(1, &message, &sig, &pub_key), "ML-DSA-44 round-trip verify");
    }

    // --- reject-truncated-payload ---
    #[test]
    fn test_reject_truncated_payload() {
        let vs = load_vectors();
        let v = &vs["reject-truncated-payload"];
        let data = from_hex(v["input"]["payload_hex"].as_str().unwrap());
        // Decode should fail — payload is truncated
        use crate::verifier::decode_payload_pub;
        assert!(decode_payload_pub(&data).is_err(), "truncated payload must fail decode");
    }

    // --- reject-entry-index-zero ---
    #[test]
    fn test_reject_entry_index_zero() {
        let vs = load_vectors();
        let v = &vs["reject-entry-index-zero"];
        let data = from_hex(v["input"]["payload_hex"].as_str().unwrap());
        use crate::verifier::decode_payload_pub;
        let p = decode_payload_pub(&data).expect("entry_index=0 is structurally valid");
        assert_eq!(p.entry_index, 0, "entry_index must be 0 in this vector");
    }

    // --- reject-tampered-tbs ---
    #[test]
    fn test_reject_tampered_tbs() {
        let vs = load_vectors();
        let v = &vs["reject-tampered-tbs"];
        let data = from_hex(v["input"]["payload_hex"].as_str().unwrap());
        let root = from_hex(v["input"]["root_hex"].as_str().unwrap());
        use crate::verifier::{decode_payload_pub, verify_inclusion_pub};
        let p = decode_payload_pub(&data).unwrap();
        let entry_hash = hash_leaf(&p.tbs);
        // Inclusion proof must fail — tampered TBS produces wrong entry hash
        assert!(
            verify_inclusion_pub(&entry_hash, p.entry_index as usize, p.tree_size as usize, &p.proof_hashes, &root).is_err(),
            "tampered TBS must fail inclusion proof"
        );
    }

    // --- reject-wrong-sig-alg ---
    #[test]
    fn test_reject_wrong_sig_alg() {
        let vs = load_vectors();
        let v = &vs["reject-wrong-sig-alg"];
        let data = from_hex(v["input"]["payload_hex"].as_str().unwrap());
        let trust_sig_alg = v["input"]["trust_config"]["sig_alg"].as_u64().unwrap() as u8;
        use crate::verifier::decode_payload_pub;
        let p = decode_payload_pub(&data).unwrap();
        // Payload sig_alg differs from trust config
        assert_ne!(p.sig_alg, trust_sig_alg, "sig_alg mismatch must be detectable");
        assert_eq!(p.sig_alg, 4, "payload claims ECDSA P-256");
        assert_eq!(trust_sig_alg, 6, "trust config expects Ed25519");
    }
}
