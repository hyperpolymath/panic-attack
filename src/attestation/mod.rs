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
        /// The embedded intent and evidence were rehashed and match the
        /// seal. False for legacy seals, whose hashes cannot be recomputed.
        content_bound: bool,
        signature_verified: bool,
    },
    /// One or more chain invariants failed.
    Failed(Vec<String>),
}

/// Verify an attestation sidecar file.
///
/// Reads the JSON file at `path`, recomputes the chain hash from the stored
/// intent/evidence/report hashes, and checks that it matches `seal.chain_hash`.
/// Under the JCS hash scheme it also rehashes the embedded intent and
/// evidence records, so editing either one after sealing is detected.
/// If `seal.signature` and `seal.public_key` are present, also verifies the
/// Ed25519 signature over the chain hash.
///
/// Returns `VerifyResult::Ok` when all checks pass, `VerifyResult::Failed`
/// with a list of failure reasons otherwise.
pub fn verify_attestation_file(path: &std::path::Path) -> anyhow::Result<VerifyResult> {
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

    verify_attestation_str(&content)
}

/// Verify an attestation envelope held in memory. See
/// [`verify_attestation_file`].
pub fn verify_attestation_str(content: &str) -> anyhow::Result<VerifyResult> {
    let tree: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| anyhow::anyhow!("parsing attestation envelope: {}", e))?;
    let envelope: A2mlEnvelope = serde_json::from_value(tree.clone())
        .map_err(|e| anyhow::anyhow!("parsing attestation envelope: {}", e))?;

    let chain = &envelope.attestation;
    let seal = &chain.seal;
    let mut failures = Vec::new();

    // Every digest must be exactly 64 lowercase hex characters. With fixed
    // widths the legacy chain input (192 bytes) and the scheme-prefixed one
    // (202 bytes) cannot coincide; without them, moving the scheme name into
    // `intent_hash` and dropping `hash_scheme` would reproduce the signed
    // bytes on the legacy path, which skips the content check.
    for (name, digest) in [
        ("intent_hash", &seal.intent_hash),
        ("evidence_hash", &seal.evidence_hash),
        ("report_hash", &seal.report_hash),
        ("chain_hash", &seal.chain_hash),
    ] {
        if !is_sha256_hex(digest) {
            failures.push(format!("{} is not a SHA-256 digest: {}", name, digest));
        }
    }
    if !failures.is_empty() {
        return Ok(VerifyResult::Failed(failures));
    }

    // Recompute chain_hash = SHA-256(hash_scheme || intent_hash || evidence_hash || report_hash)
    let computed_chain_hash = seal::chain_hash(
        &seal.hash_scheme,
        &seal.intent_hash,
        &seal.evidence_hash,
        &seal.report_hash,
    );

    if computed_chain_hash != seal.chain_hash {
        failures.push(format!(
            "chain_hash mismatch: stored={} computed={}",
            seal.chain_hash, computed_chain_hash
        ));
    }

    // Rehash the intent and evidence exactly as they appear in the file.
    // Hashing the parsed JSON rather than the typed structs keeps fields
    // this build does not know about inside the hash. Legacy seals hashed
    // serde_json struct order, which cannot be rebuilt from the file, so
    // they are reported as unbound rather than failed.
    let content_bound = match seal.hash_scheme.as_str() {
        seal::HASH_SCHEME_JCS => {
            for (name, stored) in [
                ("intent", &seal.intent_hash),
                ("evidence", &seal.evidence_hash),
            ] {
                let bytes = crate::json::to_canonical_bytes(&tree["attestation"][name])?;
                let computed = intent::sha256_str(&bytes);
                if &computed != stored {
                    failures.push(format!(
                        "{}_hash mismatch: stored={} computed={}",
                        name, stored, computed
                    ));
                }
            }
            true
        }
        seal::HASH_SCHEME_LEGACY => false,
        other => {
            failures.push(format!("unknown hash_scheme: {}", other));
            false
        }
    };

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
        content_bound,
        signature_verified,
    })
}

/// A hex-encoded SHA-256 digest as `hex::encode` writes it.
fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Seal a small scan of a temporary directory and return the sidecar
    /// exactly as `assail --attest` writes it.
    fn sealed_sidecar() -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = vec!["--verbose".to_string()];
        let mut builder = AttestationChainBuilder::begin(dir.path(), &args).expect("begin");
        builder.accumulator().record_directory("src");
        builder
            .accumulator()
            .record_file("main.rs", b"fn main() {}", "Rust");
        let report = crate::json::to_canonical_string(&serde_json::json!({"weak_points": []}))
            .expect("report");
        let envelope = builder.seal(report.as_bytes(), None).expect("seal");
        crate::json::to_canonical_string(&envelope).expect("sidecar")
    }

    fn edit(sidecar: &str, change: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut tree: serde_json::Value = serde_json::from_str(sidecar).expect("parse");
        change(&mut tree);
        serde_json::to_string_pretty(&tree).expect("serialize")
    }

    fn failures(sidecar: &str) -> Vec<String> {
        match verify_attestation_str(sidecar).expect("verify") {
            VerifyResult::Failed(reasons) => reasons,
            VerifyResult::Ok { .. } => Vec::new(),
        }
    }

    #[test]
    fn fresh_sidecar_verifies_with_content_bound() {
        match verify_attestation_str(&sealed_sidecar()).expect("verify") {
            VerifyResult::Ok { content_bound, .. } => assert!(content_bound),
            VerifyResult::Failed(reasons) => panic!("{reasons:?}"),
        }
    }

    #[test]
    fn intent_hash_is_sha256_of_hand_written_jcs() {
        // Rebuild the intent's JCS by hand (keys in code-point order, no
        // whitespace) so the test does not lean on the canonicaliser it checks.
        let tree: serde_json::Value = serde_json::from_str(&sealed_sidecar()).expect("parse");
        let intent = &tree["attestation"]["intent"];
        let field = |k: &str| intent[k].as_str().expect(k).to_string();
        let jcs = format!(
            "{{\"cli_args\":[\"--verbose\"],\"commitment_hash\":\"{}\",\"session_nonce\":\"{}\",\
             \"target_hash\":\"{}\",\"target_path\":\"{}\",\"timestamp\":\"{}\",\
             \"tool_binary_hash\":\"{}\",\"tool_version\":\"{}\"}}",
            field("commitment_hash"),
            field("session_nonce"),
            field("target_hash"),
            field("target_path"),
            field("timestamp"),
            field("tool_binary_hash"),
            field("tool_version"),
        );
        assert_eq!(
            hex::encode(Sha256::digest(jcs.as_bytes())),
            tree["attestation"]["seal"]["intent_hash"]
                .as_str()
                .expect("intent_hash")
        );
    }

    #[test]
    fn reformatting_the_sidecar_keeps_it_valid() {
        // The hashes cover JCS bytes, not the file's layout.
        let pretty = edit(&sealed_sidecar(), |_| {});
        assert!(failures(&pretty).is_empty());
    }

    #[test]
    fn editing_intent_or_evidence_after_sealing_is_detected() {
        let sidecar = sealed_sidecar();
        let tampered = edit(&sidecar, |tree| {
            tree["attestation"]["intent"]["cli_args"] = serde_json::json!(["--quiet"]);
        });
        let reasons = failures(&tampered);
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("intent_hash mismatch")),
            "{reasons:?}"
        );

        let tampered = edit(&sidecar, |tree| {
            tree["attestation"]["evidence"]["files_read"] = serde_json::json!(0);
        });
        let reasons = failures(&tampered);
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("evidence_hash mismatch")),
            "{reasons:?}"
        );
    }

    fn strip_scheme(tree: &mut serde_json::Value) {
        tree["attestation"]["seal"]
            .as_object_mut()
            .expect("seal")
            .remove("hash_scheme");
    }

    #[test]
    fn legacy_seal_verifies_but_is_not_content_bound() {
        // A seal written before `hash_scheme` existed: no field, and a
        // chain hash over the three digests alone.
        let legacy = edit(&sealed_sidecar(), |tree| {
            strip_scheme(tree);
            let seal = &tree["attestation"]["seal"];
            let digest = |k: &str| seal[k].as_str().expect(k).to_string();
            let chain = seal::chain_hash(
                seal::HASH_SCHEME_LEGACY,
                &digest("intent_hash"),
                &digest("evidence_hash"),
                &digest("report_hash"),
            );
            tree["attestation"]["seal"]["chain_hash"] = serde_json::json!(chain);
        });
        match verify_attestation_str(&legacy).expect("verify") {
            VerifyResult::Ok { content_bound, .. } => assert!(!content_bound),
            VerifyResult::Failed(reasons) => panic!("{reasons:?}"),
        }
    }

    #[test]
    fn relabelling_a_seal_as_legacy_breaks_the_chain_hash() {
        // Dropping `hash_scheme` would skip the content check, so it must
        // not verify: the scheme is inside the (signed) chain hash.
        let downgraded = edit(&sealed_sidecar(), |tree| {
            strip_scheme(tree);
            tree["attestation"]["intent"]["cli_args"] = serde_json::json!(["--quiet"]);
        });
        let reasons = failures(&downgraded);
        assert!(
            reasons.iter().any(|r| r.starts_with("chain_hash mismatch")),
            "{reasons:?}"
        );
    }

    #[test]
    fn shifting_the_scheme_into_a_digest_field_is_rejected() {
        // The legacy chain hashes `i || e || r`; the JCS chain hashes
        // `"jcs-sha256" || i || e || r`. Moving the scheme name into
        // `intent_hash` would reproduce the signed bytes exactly while
        // dropping to the legacy path, which skips the content check.
        let shifted = edit(&sealed_sidecar(), |tree| {
            strip_scheme(tree);
            let seal = &mut tree["attestation"]["seal"];
            let original = seal["intent_hash"]
                .as_str()
                .expect("intent_hash")
                .to_string();
            seal["intent_hash"] =
                serde_json::json!(format!("{}{}", seal::HASH_SCHEME_JCS, original));
            tree["attestation"]["intent"]["cli_args"] = serde_json::json!(["--quiet"]);
        });
        let reasons = failures(&shifted);
        assert!(
            reasons
                .iter()
                .any(|r| r.starts_with("intent_hash is not a SHA-256 digest")),
            "{reasons:?}"
        );
    }

    #[test]
    fn unknown_hash_scheme_fails() {
        let unknown = edit(&sealed_sidecar(), |tree| {
            tree["attestation"]["seal"]["hash_scheme"] = serde_json::json!("md5");
        });
        let reasons = failures(&unknown);
        assert!(
            reasons.iter().any(|r| r == "unknown hash_scheme: md5"),
            "{reasons:?}"
        );
    }
}
