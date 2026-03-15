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
