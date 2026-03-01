// SPDX-License-Identifier: PMPL-1.0-or-later

//! Post-execution report seal.
//!
//! After the scan completes and the report JSON is produced, the seal binds
//! the intent, evidence, and report together via a chain hash:
//!
//! ```text
//! chain_hash = SHA-256(intent_hash || evidence_hash || report_hash)
//! ```
//!
//! If any component is tampered with after sealing, the chain hash will
//! not match. Optionally, the chain hash can be signed with an Ed25519
//! private key to provide non-repudiation.

use super::intent::sha256_str;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Post-execution seal that binds the three attestation phases together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSeal {
    /// Same nonce as intent and evidence — ties all three phases together.
    pub session_nonce: String,

    /// SHA-256 of the serialised report JSON.
    pub report_hash: String,

    /// SHA-256 of the serialised intent JSON (i.e., `intent.commitment_hash`
    /// is already a commitment, but this is the hash of the full intent record).
    pub intent_hash: String,

    /// SHA-256 of the serialised evidence JSON.
    pub evidence_hash: String,

    /// `SHA-256(intent_hash || evidence_hash || report_hash)`.
    /// The binding hash that chains all three components.
    pub chain_hash: String,

    /// ISO 8601 timestamp of seal creation.
    pub sealed_at: String,

    /// Optional Ed25519 signature over `chain_hash` (hex-encoded).
    /// Present only when `--signing-key` was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Optional Ed25519 public key corresponding to the signing key (hex-encoded).
    /// Present only when a signature is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl ReportSeal {
    /// Create a seal binding the intent, evidence, and report hashes.
    ///
    /// The `intent_json` and `evidence_json` are the serialised forms of
    /// the respective structs. The `report_json` is the serialised scan
    /// report. All three are hashed independently, then combined into
    /// the chain hash.
    pub fn create(
        session_nonce: &str,
        intent_json: &[u8],
        evidence_json: &[u8],
        report_json: &[u8],
    ) -> Self {
        let intent_hash = sha256_str(intent_json);
        let evidence_hash = sha256_str(evidence_json);
        let report_hash = sha256_str(report_json);

        let chain_hash = {
            let mut hasher = Sha256::new();
            hasher.update(intent_hash.as_bytes());
            hasher.update(evidence_hash.as_bytes());
            hasher.update(report_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        Self {
            session_nonce: session_nonce.to_string(),
            report_hash,
            intent_hash,
            evidence_hash,
            chain_hash,
            sealed_at: chrono::Utc::now().to_rfc3339(),
            signature: None,
            public_key: None,
        }
    }

    /// Sign the chain hash with an Ed25519 private key.
    ///
    /// Only available when the `signing` feature is enabled. The private
    /// key is expected to be a 32-byte seed in a file (raw bytes, not PEM).
    #[cfg(feature = "signing")]
    pub fn sign(&mut self, signing_key_path: &std::path::Path) -> Result<()> {
        use ed25519_dalek::{Signer, SigningKey};

        let key_bytes = std::fs::read(signing_key_path)
            .map_err(|e| anyhow::anyhow!("reading signing key: {}", e))?;

        if key_bytes.len() != 32 {
            anyhow::bail!(
                "Ed25519 signing key must be exactly 32 bytes, got {}",
                key_bytes.len()
            );
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let sig = signing_key.sign(self.chain_hash.as_bytes());
        self.signature = Some(hex::encode(sig.to_bytes()));
        self.public_key = Some(hex::encode(verifying_key.to_bytes()));

        Ok(())
    }

    /// Stub for when the `signing` feature is not enabled.
    #[cfg(not(feature = "signing"))]
    pub fn sign(&mut self, _signing_key_path: &std::path::Path) -> Result<()> {
        anyhow::bail!(
            "Ed25519 signing requires the 'signing' feature. \
             Rebuild with: cargo build --features signing"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_chain_hash() {
        let seal = ReportSeal::create(
            &"d".repeat(64),
            b"{\"intent\": true}",
            b"{\"evidence\": true}",
            b"{\"report\": true}",
        );

        assert_eq!(seal.session_nonce.len(), 64);
        assert_eq!(seal.report_hash.len(), 64);
        assert_eq!(seal.intent_hash.len(), 64);
        assert_eq!(seal.evidence_hash.len(), 64);
        assert_eq!(seal.chain_hash.len(), 64);
        assert!(seal.signature.is_none());
        assert!(seal.public_key.is_none());
    }

    #[test]
    fn test_tamper_detection() {
        let seal_a = ReportSeal::create(
            &"e".repeat(64),
            b"{\"intent\": true}",
            b"{\"evidence\": true}",
            b"{\"report\": true}",
        );

        // Tamper with the report
        let seal_b = ReportSeal::create(
            &"e".repeat(64),
            b"{\"intent\": true}",
            b"{\"evidence\": true}",
            b"{\"report\": false}",
        );

        assert_ne!(seal_a.chain_hash, seal_b.chain_hash);
        assert_ne!(seal_a.report_hash, seal_b.report_hash);
        // Intent and evidence hashes unchanged
        assert_eq!(seal_a.intent_hash, seal_b.intent_hash);
        assert_eq!(seal_a.evidence_hash, seal_b.evidence_hash);
    }
}
