//! Signature verification for MTA-QR.

use super::{ALG_ED25519, ALG_ECDSA_P256, ALG_ML_DSA_44};

use ed25519_dalek::{Signature as Ed25519Sig, VerifyingKey};
use ed25519_dalek::Verifier as Ed25519Verifier;
use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256VerifyingKey};
use sha2::{Sha256, Digest};
use ml_dsa::{MlDsa44, KeyGen, EncodedVerifyingKey, EncodedSignature};

/// Verify a raw signature over `message` using the given algorithm and public key.
pub fn verify(alg: u8, message: &[u8], sig: &[u8], pub_key: &[u8]) -> bool {
    match alg {
        ALG_ED25519    => verify_ed25519(message, sig, pub_key),
        ALG_ECDSA_P256 => verify_ecdsa_p256(message, sig, pub_key),
        ALG_ML_DSA_44  => verify_ml_dsa_44(message, sig, pub_key),
        _              => false,
    }
}

fn verify_ed25519(message: &[u8], sig: &[u8], pub_key: &[u8]) -> bool {
    if pub_key.len() != 32 || sig.len() != 64 { return false; }
    let Ok(key_bytes) = pub_key.try_into() else { return false; };
    let Ok(vk) = VerifyingKey::from_bytes(key_bytes) else { return false; };
    let Ok(signature) = Ed25519Sig::from_slice(sig) else { return false; };
    vk.verify(message, &signature).is_ok()
}

fn verify_ecdsa_p256(message: &[u8], sig: &[u8], pub_key: &[u8]) -> bool {
    if sig.len() != 64 || pub_key.len() != 65 || pub_key[0] != 0x04 { return false; }
    let Ok(vk) = P256VerifyingKey::from_sec1_bytes(pub_key) else { return false; };
    let Ok(signature) = P256Sig::from_slice(sig) else { return false; };
    let digest = Sha256::digest(message);
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(&digest, &signature).is_ok()
}

fn verify_ml_dsa_44(message: &[u8], sig: &[u8], pub_key: &[u8]) -> bool {
    let Ok(pub_arr): Result<[u8; 1312], _> = pub_key.try_into() else { return false; };
    let Ok(sig_arr): Result<[u8; 2420], _> = sig.try_into()     else { return false; };
    let enc_vk  = EncodedVerifyingKey::<MlDsa44>::from(pub_arr);
    let enc_sig = EncodedSignature::<MlDsa44>::from(sig_arr);
    let vk      = ml_dsa::VerifyingKey::<MlDsa44>::decode(&enc_vk);
    let Some(signature) = ml_dsa::Signature::<MlDsa44>::decode(&enc_sig) else { return false; };
    use ml_dsa::signature::Verifier;
    vk.verify(message, &signature).is_ok()
}