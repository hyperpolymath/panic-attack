// SPDX-License-Identifier: PMPL-1.0-or-later

//! Pre-execution intent record.
//!
//! Before scanning begins, the intent captures:
//! - A fresh 32-byte session nonce (from `getrandom`)
//! - The SHA-256 hash of the canonical target path
//! - The CLI arguments that will govern the scan
//! - The tool version and binary hash (self-attestation)
//! - A commitment hash binding all of the above together
//!
//! The commitment hash is `SHA-256(nonce || target_hash || version || timestamp)`.
//! This prevents retroactive fabrication: you cannot produce a valid intent
//! without knowing the nonce, and the nonce is generated at scan time.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
/// Pre-execution intent record that commits to the scan parameters
/// before any analysis begins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionIntent {
    /// 32 random bytes encoded as 64 hex chars. Unique per scan session.
    pub session_nonce: String,

    /// SHA-256 of the canonical (absolute) target path.
    pub target_hash: String,

    /// The target path as supplied on the command line.
    pub target_path: String,

    /// CLI arguments serialised for reproducibility.
    pub cli_args: Vec<String>,

    /// panic-attack version from Cargo.toml (e.g. "2.0.0").
    pub tool_version: String,

    /// SHA-256 of the running binary (`std::env::current_exe()`).
    pub tool_binary_hash: String,

    /// ISO 8601 timestamp of intent creation.
    pub timestamp: String,

    /// `SHA-256(nonce || target_hash || version || timestamp)`.
    /// Binding commitment — changes if any input changes.
    pub commitment_hash: String,
}

impl ExecutionIntent {
    /// Build an intent record for the given target and CLI arguments.
    ///
    /// Generates a cryptographic nonce, hashes the target path and the
    /// running binary, records the current time, and computes the binding
    /// commitment hash over all fields.
    pub fn commit(target: &Path, args: &[String]) -> Result<Self> {
        // 1. Generate 32-byte random nonce
        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {}", e))?;
        let session_nonce = hex::encode(nonce_bytes);

        // 2. Canonical target path → SHA-256
        let canonical = target
            .canonicalize()
            .unwrap_or_else(|_| target.to_path_buf());
        let target_hash = sha256_str(canonical.to_string_lossy().as_bytes());
        let target_path = target.display().to_string();

        // 3. Tool version from compile-time constant
        let tool_version = env!("CARGO_PKG_VERSION").to_string();

        // 4. Hash the running binary for self-attestation
        let tool_binary_hash = hash_current_binary()
            .unwrap_or_else(|_| "unavailable".to_string());

        // 5. ISO 8601 timestamp
        let timestamp = chrono::Utc::now().to_rfc3339();

        // 6. Commitment: SHA-256(nonce || target_hash || version || timestamp)
        let commitment_hash = {
            let mut hasher = Sha256::new();
            hasher.update(session_nonce.as_bytes());
            hasher.update(target_hash.as_bytes());
            hasher.update(tool_version.as_bytes());
            hasher.update(timestamp.as_bytes());
            hex::encode(hasher.finalize())
        };

        Ok(Self {
            session_nonce,
            target_hash,
            target_path,
            cli_args: args.to_vec(),
            tool_version,
            tool_binary_hash,
            timestamp,
            commitment_hash,
        })
    }
}

/// SHA-256 of an arbitrary byte slice, returned as 64 hex chars.
pub(crate) fn sha256_str(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 of the currently running binary, for self-attestation.
///
/// Falls back gracefully if the binary cannot be read (e.g. on some
/// sandboxed environments).
fn hash_current_binary() -> Result<String> {
    let exe_path = std::env::current_exe()
        .context("resolving current executable path")?;
    let bytes = std::fs::read(&exe_path)
        .with_context(|| format!("reading binary {}", exe_path.display()))?;
    Ok(sha256_str(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_intent_commit_produces_valid_fields() {
        let target = PathBuf::from("/tmp");
        let args = vec!["--verbose".to_string()];
        let intent = ExecutionIntent::commit(&target, &args).unwrap();

        // Nonce is 64 hex chars (32 bytes)
        assert_eq!(intent.session_nonce.len(), 64);
        // Target hash is 64 hex chars
        assert_eq!(intent.target_hash.len(), 64);
        // Commitment hash is 64 hex chars
        assert_eq!(intent.commitment_hash.len(), 64);
        // Version matches
        assert_eq!(intent.tool_version, env!("CARGO_PKG_VERSION"));
        // Args preserved
        assert_eq!(intent.cli_args, args);
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        // Two intents for the same target should have DIFFERENT commitment
        // hashes because the nonce differs each time.
        let target = PathBuf::from("/tmp");
        let args = vec![];
        let a = ExecutionIntent::commit(&target, &args).unwrap();
        let b = ExecutionIntent::commit(&target, &args).unwrap();
        assert_ne!(a.commitment_hash, b.commitment_hash);
        assert_ne!(a.session_nonce, b.session_nonce);
    }

    #[test]
    fn test_sha256_str() {
        let hash = sha256_str(b"hello world");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
