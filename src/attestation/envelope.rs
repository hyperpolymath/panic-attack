// SPDX-License-Identifier: PMPL-1.0-or-later

//! A2ML envelope wrapping the attestation chain.
//!
//! The envelope provides a standard metadata wrapper that identifies the
//! attestation as a Trustfile-format document. DYADT and K9 contractiles
//! can parse the envelope to extract the chain and verify its integrity.
//!
//! The envelope is deliberately minimal — it carries the chain but does
//! not duplicate any of the chain's fields. The `decision_hash` field
//! mirrors the report hash, providing a single value that DYADT can
//! match against the scan result file.

use super::evidence::ExecutionEvidence;
use super::intent::ExecutionIntent;
use super::seal::ReportSeal;
use serde::{Deserialize, Serialize};

/// The complete three-phase attestation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChain {
    /// Phase 1: pre-execution intent.
    pub intent: ExecutionIntent,

    /// Phase 2: execution evidence.
    pub evidence: ExecutionEvidence,

    /// Phase 3: post-execution seal.
    pub seal: ReportSeal,
}

/// A2ML-format envelope wrapping the attestation chain.
///
/// This is the top-level structure written to the `.attestation.json`
/// sidecar file alongside the scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2mlEnvelope {
    /// A2ML specification version.
    pub a2ml_version: String,

    /// Envelope type identifier. Always `"trustfile"` for attestations.
    pub envelope_type: String,

    /// Tool that issued this attestation (e.g. `"panic-attack/2.0.0"`).
    pub issuer: String,

    /// ISO 8601 timestamp of envelope creation.
    pub issued_at: String,

    /// SHA-256 of the report — the "decision" being attested.
    /// Equal to `attestation.seal.report_hash`.
    pub decision_hash: String,

    /// The three-phase attestation chain.
    pub attestation: AttestationChain,
}

impl A2mlEnvelope {
    /// Wrap a completed attestation chain in an A2ML envelope.
    pub fn wrap(chain: AttestationChain) -> Self {
        let decision_hash = chain.seal.report_hash.clone();
        Self {
            a2ml_version: "1.0.0".to_string(),
            envelope_type: "trustfile".to_string(),
            issuer: format!("panic-attack/{}", env!("CARGO_PKG_VERSION")),
            issued_at: chrono::Utc::now().to_rfc3339(),
            decision_hash,
            attestation: chain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::evidence::ExecutionEvidence;
    use crate::attestation::intent::ExecutionIntent;
    use crate::attestation::seal::ReportSeal;

    fn mock_chain() -> AttestationChain {
        let intent = ExecutionIntent {
            session_nonce: "a".repeat(64),
            target_hash: "b".repeat(64),
            target_path: "/tmp/test".to_string(),
            cli_args: vec![],
            tool_version: "2.0.0".to_string(),
            tool_binary_hash: "c".repeat(64),
            timestamp: "2026-03-01T00:00:00Z".to_string(),
            commitment_hash: "d".repeat(64),
        };

        let evidence = ExecutionEvidence {
            session_nonce: "a".repeat(64),
            files_read: 10,
            bytes_read: 5000,
            directories_traversed: 3,
            rolling_content_hash: "e".repeat(64),
            wall_clock_ms: 150,
            cpu_time_ms: 120,
            peak_rss: 1024 * 1024,
            checkpoints: vec![],
            languages_detected: vec!["Rust".to_string()],
            evidence_hash: "f".repeat(64),
        };

        let seal = ReportSeal {
            session_nonce: "a".repeat(64),
            report_hash: "0".repeat(64),
            intent_hash: "1".repeat(64),
            evidence_hash: "2".repeat(64),
            chain_hash: "3".repeat(64),
            sealed_at: "2026-03-01T00:00:01Z".to_string(),
            signature: None,
            public_key: None,
        };

        AttestationChain {
            intent,
            evidence,
            seal,
        }
    }

    #[test]
    fn test_envelope_wraps_chain() {
        let chain = mock_chain();
        let envelope = A2mlEnvelope::wrap(chain);

        assert_eq!(envelope.a2ml_version, "1.0.0");
        assert_eq!(envelope.envelope_type, "trustfile");
        assert!(envelope.issuer.starts_with("panic-attack/"));
        assert_eq!(envelope.decision_hash, "0".repeat(64));
    }

    #[test]
    fn test_envelope_serialises_to_json() {
        let chain = mock_chain();
        let envelope = A2mlEnvelope::wrap(chain);
        let json = serde_json::to_string_pretty(&envelope).unwrap();
        assert!(json.contains("\"a2ml_version\""));
        assert!(json.contains("\"attestation\""));
        assert!(json.contains("\"intent\""));
        assert!(json.contains("\"evidence\""));
        assert!(json.contains("\"seal\""));
    }
}
