//! LocalSigner — raw key material, FOR TESTING ONLY.

use crate::signing::{BoxFuture, Signer, ALG_ED25519, ALG_ECDSA_P256, ALG_ML_DSA_44};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::Signer as DalekSigner;
use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Sig};
use sha2::{Sha256, Digest};
use ml_dsa::{MlDsa44, KeyGen, EncodedSignature, EncodedVerifyingKey};

fn build_key_name(label: &str, _pub_bytes: &[u8]) -> String {
    // Per c2sp.org/signed-note: key name in signature lines is the bare label.
    // The key hash and public key go in the trust config verifier key string only.
    label.to_string()
}

struct LocalEd25519 {
    key_name: String,
    sk: Ed25519SigningKey,
    pub_key: Vec<u8>,
}

impl Signer for LocalEd25519 {
    fn alg(&self) -> u8        { ALG_ED25519 }
    fn key_name(&self) -> &str { &self.key_name }
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.sk.sign(message).to_bytes().to_vec()) })
    }
    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.pub_key.clone()) })
    }
}

struct LocalEcdsaP256 {
    key_name: String,
    sk: P256SigningKey,
    pub_key: Vec<u8>,
}

impl Signer for LocalEcdsaP256 {
    fn alg(&self) -> u8        { ALG_ECDSA_P256 }
    fn key_name(&self) -> &str { &self.key_name }
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let digest = Sha256::digest(message);
            let sig: P256Sig = self.sk.sign_prehash(&digest)
                .map_err(|e| anyhow!("P256 sign: {e}"))?;
            Ok(sig.to_bytes().to_vec())
        })
    }
    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.pub_key.clone()) })
    }
}

struct LocalMlDsa44 {
    key_name: String,
    sk: ml_dsa::SigningKey<MlDsa44>,
    pub_key: Vec<u8>,
}

impl Signer for LocalMlDsa44 {
    fn alg(&self) -> u8        { ALG_ML_DSA_44 }
    fn key_name(&self) -> &str { &self.key_name }
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            use ml_dsa::signature::Signer as MlSigner;
            let sig: ml_dsa::Signature<MlDsa44> = self.sk.sign(message);
            let enc: EncodedSignature<MlDsa44>  = sig.encode();
            Ok(enc.as_slice().to_vec())
        })
    }
    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { Ok(self.pub_key.clone()) })
    }
}

/// Constructors for local signers.
pub struct LocalSigner;

impl LocalSigner {
    pub fn ed25519(seed: &[u8]) -> Result<Box<dyn Signer>> {
        let seed: [u8; 32] = seed.try_into()
            .map_err(|_| anyhow!("Ed25519 seed must be 32 bytes"))?;
        let sk      = Ed25519SigningKey::from_bytes(&seed);
        let pub_key = sk.verifying_key().to_bytes().to_vec();
        Ok(Box::new(LocalEd25519 { key_name: build_key_name("local-Ed25519", &pub_key), sk, pub_key }))
    }

    pub fn ecdsa_p256(scalar: &[u8]) -> Result<Box<dyn Signer>> {
        let scalar: [u8; 32] = scalar.try_into()
            .map_err(|_| anyhow!("P-256 scalar must be 32 bytes"))?;
        let sk = P256SigningKey::from_bytes((&scalar).into())
            .map_err(|e| anyhow!("invalid P-256 scalar: {e}"))?;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let pub_key  = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        Ok(Box::new(LocalEcdsaP256 { key_name: build_key_name("local-ECDSA-P256", &pub_key), sk, pub_key }))
    }

    pub fn ml_dsa_44(seed: &[u8]) -> Result<Box<dyn Signer>> {
        let seed_arr: [u8; 32] = seed.try_into()
            .map_err(|_| anyhow!("ML-DSA-44 seed must be 32 bytes"))?;
        let seed_b32 = ml_dsa::B32::from(seed_arr);
        let kp       = MlDsa44::from_seed(&seed_b32);
        let enc_vk: EncodedVerifyingKey<MlDsa44> = kp.verifying_key().encode();
        let pub_key: Vec<u8> = enc_vk.as_slice().to_vec();
        let sk       = kp.signing_key().clone();
        Ok(Box::new(LocalMlDsa44 { key_name: build_key_name("local-ML-DSA-44", &pub_key), sk, pub_key }))
    }
}
