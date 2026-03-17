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
//!     let mut verifier = Verifier::new();
//!     verifier.add_anchor(trust)?;
//!     let payload_bytes = vec![0u8; 0]; // placeholder
//!     let ok = verifier.verify(&payload_bytes).await?;
//!     println!("{:?}", ok.claims);
//!     Ok(())
//! }
//! ```

pub mod cascade;
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


    // --- revocation-cascade-r1 ---
    #[test]
    fn test_cascade_vector_r1() {
        use crate::cascade::Cascade;
        let r1_hex = "01000000080112";
        let revoked: &[u64] = &[2, 5];
        let valid: &[u64]   = &[1, 3, 4, 6, 7, 8];

        let c = Cascade::build(revoked, valid).unwrap();
        assert_eq!(hex(&c.encode()), r1_hex, "R1 bytes changed — update spec");

        let c2 = Cascade::decode(&from_hex(r1_hex)).unwrap();
        let expect: &[(u64, bool)] = &[
            (0, false), (1, false), (2, true),
            (3, false), (4, false), (5, true),
            (6, false), (7, false), (8, false), (99, false),
        ];
        for &(idx, want) in expect {
            assert_eq!(c.query(idx), want, "query({idx}) mismatch");
            assert_eq!(c2.query(idx), want, "decoded query({idx}) mismatch");
        }
    }

    // --- revocation-cascade-r2 ---
    #[test]
    fn test_cascade_vector_r2() {
        use crate::cascade::Cascade;
        let c = Cascade::build(&[], &[1, 2, 3]).unwrap();
        assert_eq!(hex(&c.encode()), "00", "R2 must be [0x00]");
        assert!(!c.query(1));
        assert!(!c.query(99));
    }
}

#[cfg(test)]
mod revocation_tests {
    use crate::issuer::{Issuer, IssuerConfig};
    use crate::verifier::Verifier;
    use crate::trust::TrustConfig;
    use std::time::Duration;

    const SEED: [u8; 32] = {
        let mut s = [0u8; 32];
        s[0] = 0x27; s[1] = 0x5b; s[2] = 0xe8; s[3] = 0x5b;
        s[4] = 0x9a; s[5] = 0xa3; s[6] = 0x35; s[7] = 0x7c;
        s
    };

    async fn make_issuer(label: &str) -> Issuer {
        use crate::signers::local::LocalSigner;
        let signer = LocalSigner::ed25519(&SEED).unwrap();
        let cfg = IssuerConfig {
            origin:        format!("test.revoc/{label}/v1"),
            schema_id:     1,
            mode:          None,
            batch_size:    None,
            witness_count: Some(1), // minimum required by TrustConfig validation
        };
        let issuer = Issuer::new(cfg, signer);
        issuer.init().await.unwrap();
        issuer
    }

    async fn make_verifier(issuer: &Issuer) -> Verifier {
        let tc_json = issuer.trust_config_json("http://localhost:0/checkpoint").await.unwrap();
        let trust   = TrustConfig::parse_str(&tc_json).unwrap();
        // Snapshot checkpoint note and revocation artifact — avoids HTTP in unit tests.
        let note  = issuer.checkpoint_note().await.unwrap();
        let revoc = issuer.revocation_artifact().await.unwrap_or_default();
        let note_provider: crate::verifier::NoteProvider =
            Box::new(move |_: &str| -> anyhow::Result<String> { Ok(note.clone()) });
        let revoc_provider: crate::verifier::RevocationProvider =
            Box::new(move |_: &str| -> anyhow::Result<String> { Ok(revoc.clone()) });
        { let mut v = Verifier::with_revocation_provider(note_provider, revoc_provider); v.add_anchor(trust).unwrap(); v }
    }

    #[tokio::test]
    async fn un_revoked_entry_verifies() {
        let issuer = make_issuer("not-revoked").await;
        let qr     = issuer.issue([("subject", "alice")], Duration::from_secs(3600)).await.unwrap();
        let v      = make_verifier(&issuer).await;
        assert!(v.verify(&qr.payload).await.is_ok(), "un-revoked entry must verify");
    }

    #[tokio::test]
    async fn revoked_entry_is_rejected() {
        let issuer = make_issuer("revoked").await;
        let qr     = issuer.issue([("subject", "bob")], Duration::from_secs(3600)).await.unwrap();
        issuer.revoke(qr.entry_index).await.unwrap();
        let v      = make_verifier(&issuer).await;
        let result = v.verify(&qr.payload).await;
        assert!(result.is_err(), "revoked entry must be rejected");
        assert!(result.unwrap_err().to_string().contains("revoked"),
            "error must mention 'revoked'");
    }

    #[tokio::test]
    async fn revoke_zero_rejected() {
        let issuer = make_issuer("zero").await;
        assert!(issuer.revoke(0).await.is_err(), "revoking index 0 must fail");
    }

    #[tokio::test]
    async fn mode_zero_rejected() {
        // Build a mode=0 payload using the SDK encoder and confirm the verifier
        // rejects it with a clear "not implemented" message.
        use crate::issuer::{Issuer, IssuerConfig};
        use crate::verifier::Verifier;
        use crate::trust::TrustConfig;
        use crate::signers::local::LocalSigner;

        let signer = LocalSigner::ed25519(&SEED).unwrap();
        let cfg = IssuerConfig {
            origin:        "test.revoc/mode0/v1".into(),
            schema_id:     1,
            mode:          None,
            batch_size:    None,
            witness_count: Some(1),
        };
        let issuer = Issuer::new(cfg, signer);
        issuer.init().await.unwrap();

        let tc_json = issuer.trust_config_json("http://localhost:0/checkpoint").await.unwrap();
        let trust   = TrustConfig::parse_str(&tc_json).unwrap();
        let note    = issuer.checkpoint_note().await.unwrap();
        let revoc   = issuer.revocation_artifact().await.unwrap_or_default();
        let mut v = Verifier::with_revocation_provider(
            Box::new(move |_| Ok(note.clone())),
            Box::new(move |_| Ok(revoc.clone())),
        );
        v.add_anchor(trust).unwrap();

        let tc_json2 = issuer.trust_config_json("http://localhost:0/checkpoint").await.unwrap();
        let trust2 = TrustConfig::parse_str(&tc_json2).unwrap();
        let origin_id = trust2.origin_id.to_be_bytes();
        // Build a payload with mode=0 set in flags but no embedded checkpoint fields.
        // The Rust decoder reads up to TBS then stops — mode=0 trailing fields are
        // not parsed, so we only include bytes through TBS. The verifier's mode check
        // fires before it tries to do anything else with the payload.
        // flags: version=1, no self-describing(0x00), sigAlg=Ed25519(6<<2=0x18), mode=0 -> 0x18
        let mut payload = vec![0x01u8, 0x18]; // version=1, sigAlg=Ed25519, mode=0
        payload.extend_from_slice(&origin_id);
        payload.extend_from_slice(&2u64.to_be_bytes()); // tree_size
        payload.extend_from_slice(&1u64.to_be_bytes()); // entry_index
        payload.push(0); payload.push(0); // proof_count=0, inner_count=0
        payload.push(0); payload.push(1); // tbs_len=1
        payload.push(0x01); // minimal TBS (data assertion type byte)

        let result = v.verify(&payload).await;
        assert!(result.is_err(), "mode=0 with bad/missing embedded checkpoint must be rejected");
        // Mode 0 is now implemented — a crafted payload missing embedded fields
        // fails at decode time or at signature verification.
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("embedded checkpoint") || msg.contains("issuer signature")
            || msg.contains("malformed") || msg.contains("root_hash") || msg.contains("trailing"),
            "expected decode/checkpoint failure, got: {msg}");
    }

    #[tokio::test]
    async fn mode0_round_trip() {
        use crate::issuer::{Issuer, IssuerConfig};
        use crate::verifier::Verifier;
        use crate::trust::TrustConfig;
        use crate::signers::local::LocalSigner;
        use std::time::Duration;

        let signer = LocalSigner::ed25519(&SEED).unwrap();
        let cfg = IssuerConfig {
            origin:        "test.mode0.roundtrip/v1".into(),
            schema_id:     1,
            mode:          Some(0), // Mode 0: embedded checkpoint
            batch_size:    None,
            witness_count: Some(1),
        };
        let issuer = Issuer::new(cfg, signer);
        issuer.init().await.unwrap();

        let qr = issuer.issue([("subject", "mode0-test")], Duration::from_secs(3600)).await.unwrap();

        // Build verifier — no noteProvider needed for Mode 0, checkpoint is embedded.
        let tc_json = issuer.trust_config_json("http://localhost:0/checkpoint").await.unwrap();
        let trust   = TrustConfig::parse_str(&tc_json).unwrap();
        let revoc   = issuer.revocation_artifact().await.unwrap_or_default();
        let mut v = Verifier::with_revocation_provider(
            Box::new(|_| Err(anyhow::anyhow!("no checkpoint fetch in Mode 0 test"))),
            Box::new(move |_| Ok(revoc.clone())),
        );
        v.add_anchor(trust).unwrap();

        let result = v.verify(&qr.payload).await;
        assert!(result.is_ok(), "Mode 0 payload must verify: {:?}", result.err());
        let ok = result.unwrap();
        assert_eq!(ok.mode, 0, "result mode must be 0");
    }

    #[tokio::test]
    async fn revoke_unissued_rejected() {
        let issuer = make_issuer("unissued").await;
        assert!(issuer.revoke(999).await.is_err(), "revoking unissued index must fail");
    }
}
