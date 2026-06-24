// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Attestation chain for panic-attack scan results.
//!
//! Provides a three-phase cryptographic attestation mechanism that proves
//! panic-attack genuinely performed a static analysis scan. The chain is:
//!
//! 1. **Intent** (pre-execution): Records what will be scanned, generates a
//!    session nonce, and commits to the target and tool version.
//! 2. **Evidence** (during execution): Accumulates a rolling hash of every
//!    file read, counting bytes, files, directories, and wall-clock time.
//! 3. **Seal** (post-execution): Binds the intent, evidence, and report
//!    hashes together into a single chain hash, with optional Ed25519 signing.
//!
//! The chain is wrapped in an A2ML envelope for interoperability with
//! DYADT verification and K9 contractile validation.
//!
//! ## Threat Model
//!
//! Without attestation, a fabricated JSON report is indistinguishable from
//! a genuine scan result. Attestation raises the bar: an attacker must now
//! replicate the exact rolling hash of file contents, produce plausible
//! resource usage metrics, and (if signing is enabled) possess the private
//! key. DYADT can then verify the chain before accepting findings.

pub mod chain;
pub mod envelope;
pub mod evidence;
pub mod intent;
pub mod seal;

pub use chain::AttestationChainBuilder;
pub use envelope::A2mlEnvelope;
#[allow(unused_imports)]
pub use evidence::{EvidenceAccumulator, ExecutionEvidence};
#[allow(unused_imports)]
pub use intent::ExecutionIntent;
#[allow(unused_imports)]
pub use seal::ReportSeal;

// ============================================================================
// Verification
// ============================================================================

/// Outcome of an attestation verification run.
#[derive(Debug)]
pub enum VerifyResult {
    /// All chain invariants pass; signature verified if present.
    Ok {
        issuer: String,
        issued_at: String,
        chain_hash: String,
        signature_verified: bool,
    },
    /// One or more chain invariants failed.
    Failed(Vec<String>),
}

/// Verify an attestation sidecar file.
///
/// Reads the JSON file at `path`, recomputes the chain hash from the stored
/// intent/evidence/report hashes, and checks that it matches `seal.chain_hash`.
/// If `seal.signature` and `seal.public_key` are present, also verifies the
/// Ed25519 signature over the chain hash.
///
/// Returns `VerifyResult::Ok` when all checks pass, `VerifyResult::Failed`
/// with a list of failure reasons otherwise.
pub fn verify_attestation_file(path: &std::path::Path) -> anyhow::Result<VerifyResult> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    // Attestation envelopes are JSON. They embed three hashes plus a small
    // signature; legitimate envelopes are well under 1 MiB. Capping at
    // 16 MiB stops a malicious or accidental input from exhausting memory
    // before verification can even begin.
    const ATTESTATION_FILE_READ_LIMIT: u64 = 16 * 1024 * 1024;

    let mut content = String::new();
    std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("opening {}: {}", path.display(), e))?
        .take(ATTESTATION_FILE_READ_LIMIT)
        .read_to_string(&mut content)
        .map_err(|e| anyhow::anyhow!("reading {}: {}", path.display(), e))?;

    let envelope: A2mlEnvelope = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("parsing attestation envelope: {}", e))?;

    let chain = &envelope.attestation;
    let seal = &chain.seal;
    let mut failures = Vec::new();

    // Recompute chain_hash = SHA-256(intent_hash || evidence_hash || report_hash)
    let mut hasher = Sha256::new();
    hasher.update(seal.intent_hash.as_bytes());
    hasher.update(seal.evidence_hash.as_bytes());
    hasher.update(seal.report_hash.as_bytes());
    let computed_chain_hash = hex::encode(hasher.finalize());

    if computed_chain_hash != seal.chain_hash {
        failures.push(format!(
            "chain_hash mismatch: stored={} computed={}",
            seal.chain_hash, computed_chain_hash
        ));
    }

    // decision_hash in the envelope must match seal.report_hash
    if envelope.decision_hash != seal.report_hash {
        failures.push(format!(
            "decision_hash mismatch: envelope={} seal={}",
            envelope.decision_hash, seal.report_hash
        ));
    }

    // Ed25519 signature verification (requires `signing` feature)
    let signature_verified = verify_signature(seal, &mut failures);

    if !failures.is_empty() {
        return Ok(VerifyResult::Failed(failures));
    }

    Ok(VerifyResult::Ok {
        issuer: envelope.issuer.clone(),
        issued_at: envelope.issued_at.clone(),
        chain_hash: seal.chain_hash.clone(),
        signature_verified,
    })
}

#[cfg(feature = "signing")]
fn verify_signature(seal: &ReportSeal, failures: &mut Vec<String>) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    let (sig_hex, pk_hex) = match (&seal.signature, &seal.public_key) {
        (Some(s), Some(k)) => (s, k),
        _ => return false, // no signature present — skip
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => {
            failures.push("signature field is not valid hex".to_string());
            return false;
        }
    };

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(_) => {
            failures.push("public_key field is not valid hex".to_string());
            return false;
        }
    };

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            failures.push("signature must be 64 bytes".to_string());
            return false;
        }
    };

    let pk_array: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            failures.push("public_key must be 32 bytes".to_string());
            return false;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(e) => {
            failures.push(format!("invalid Ed25519 public key: {}", e));
            return false;
        }
    };

    let signature = Signature::from_bytes(&sig_array);
    use ed25519_dalek::Verifier;
    match verifying_key.verify(seal.chain_hash.as_bytes(), &signature) {
        Ok(()) => true,
        Err(e) => {
            failures.push(format!("Ed25519 signature verification failed: {}", e));
            false
        }
    }
}

#[cfg(not(feature = "signing"))]
fn verify_signature(_seal: &ReportSeal, _failures: &mut Vec<String>) -> bool {
    false
}
