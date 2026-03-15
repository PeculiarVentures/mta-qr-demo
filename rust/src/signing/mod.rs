//! Core signing abstraction for MTA-QR.
//!
//! The SDK never holds private key material. All signing operations go through
//! the [`Signer`] trait, allowing GoodKey, local keys, or any compliant backend
//! to be used interchangeably.

pub mod verify;

use std::future::Future;
use std::pin::Pin;

/// Wire algorithm identifier for ML-DSA-44 (FIPS 204).
pub const ALG_ML_DSA_44:   u8 = 1;
/// Wire algorithm identifier for ECDSA P-256 / SHA-256, raw r||s wire format.
pub const ALG_ECDSA_P256:  u8 = 4;
/// Wire algorithm identifier for Ed25519.
pub const ALG_ED25519:     u8 = 6;

/// Returns a human-readable algorithm name.
pub fn alg_name(alg: u8) -> &'static str {
    match alg {
        ALG_ED25519    => "Ed25519",
        ALG_ECDSA_P256 => "ECDSA-P256",
        ALG_ML_DSA_44  => "ML-DSA-44",
        _              => "unknown",
    }
}

/// Expected raw signature byte length for an algorithm.
///
/// Ed25519 and ECDSA-P256 both return 64 — never use length alone to identify
/// algorithm. Always dispatch using the `sig_alg` from the trust config.
pub fn sig_len(alg: u8) -> usize {
    match alg {
        ALG_ED25519    => 64,
        ALG_ECDSA_P256 => 64,
        ALG_ML_DSA_44  => 2420,
        _              => 0,
    }
}

/// Expected raw public key byte length for an algorithm.
pub fn pub_key_len(alg: u8) -> usize {
    match alg {
        ALG_ED25519    => 32,
        ALG_ECDSA_P256 => 65,   // uncompressed 0x04 || X || Y
        ALG_ML_DSA_44  => 1312,
        _              => 0,
    }
}

/// Boxed future alias for async trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Blanket impl so `Box<dyn Signer>` satisfies `impl Signer` bounds.
impl Signer for Box<dyn Signer> {
    fn alg(&self) -> u8        { (**self).alg() }
    fn key_name(&self) -> &str { (**self).key_name() }
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, anyhow::Result<Vec<u8>>> {
        (**self).sign(message)
    }
    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, anyhow::Result<Vec<u8>>> {
        (**self).public_key_bytes()
    }
}

/// The only interface the Issuer needs from a key backend.
///
/// Implementations must be `Send + Sync` — the Issuer holds a `Arc<dyn Signer>`
/// and may sign from multiple tasks.
///
/// - `alg()` and `key_name()` are synchronous: they describe the key's identity
///   and must be available without a network call.
/// - `sign()` and `public_key_bytes()` are async: they may call GoodKey or an
///   HSM over the network.
pub trait Signer: Send + Sync {
    /// Wire algorithm identifier.
    fn alg(&self) -> u8;

    /// Bare key name as it appears in tlog-checkpoint note signature lines.
    /// Per c2sp.org/signed-note: just the human name. The full verifier key
    /// string (name+hex_keyid+base64(type+pub)) belongs in the trust config only.
    fn key_name(&self) -> &str;

    /// Sign a raw message. Returns the raw signature bytes.
    ///
    /// The signer handles any internal hashing required by the algorithm.
    /// The SDK always passes the full message, never a pre-computed hash.
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, anyhow::Result<Vec<u8>>>;

    /// Raw public key bytes in the wire encoding for the algorithm.
    fn public_key_bytes<'a>(&'a self) -> BoxFuture<'a, anyhow::Result<Vec<u8>>>;
}
