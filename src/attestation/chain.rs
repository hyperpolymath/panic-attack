// SPDX-License-Identifier: PMPL-1.0-or-later

//! # Attestation Chain Orchestrator
//!
//! This module is the central coordinator of the three-phase attestation
//! lifecycle. It is the only module that touches all three phases — intent,
//! evidence, and seal — and is responsible for ensuring they are wired
//! together correctly.
//!
//! ## The Three Phases
//!
//! The attestation chain follows a strict temporal sequence:
//!
//! 1. **Intent** (before scanning): `begin()` generates a fresh 32-byte
//!    nonce via `getrandom`, hashes the target path and tool binary,
//!    records the CLI arguments, and computes a commitment hash that
//!    binds nonce + target + version + timestamp. This happens BEFORE
//!    any file I/O. The intent is stored in `self.intent`.
//!
//! 2. **Evidence** (during scanning): The evidence accumulator is exposed
//!    via `accumulator()` and wired into `analyzer.rs`. As the scanner
//!    reads each file, `record_file(path, content, language)` is called,
//!    which updates a rolling SHA-256 hash chain (each file's content
//!    hash is fed into the running hasher alongside the previous state).
//!    Directory traversals are recorded via `record_directory()`.
//!    Checkpoints are emitted every 100 files. The accumulator lives in
//!    `self.accumulator` as `Option<EvidenceAccumulator>` — the `Option`
//!    is necessary because `seal()` consumes it via `take()`.
//!
//! 3. **Seal** (after scanning): `seal()` finalises the accumulator
//!    (which records wall clock time, CPU time, and peak RSS), serialises
//!    intent and evidence to JSON, then computes:
//!      - `intent_hash`    = SHA-256 of the serialised intent JSON
//!      - `evidence_hash`  = SHA-256 of the serialised evidence JSON
//!      - `report_hash`    = SHA-256 of the report JSON bytes
//!      - `chain_hash`     = SHA-256(intent_hash || evidence_hash || report_hash)
//!    The chain_hash is the cryptographic root — if any component changes,
//!    chain_hash changes. Optionally, chain_hash is signed with Ed25519.
//!    Everything is wrapped in an A2ML envelope with `envelope_type: "trustfile"`.
//!
//! ## Data Flow
//!
//! ```text
//! main.rs: --attest flag
//!   │
//!   ▼
//! AttestationChainBuilder::begin(target, args)
//!   │  └─ ExecutionIntent::commit() → generates nonce, hashes target/binary
//!   │  └─ EvidenceAccumulator::new(nonce) → empty accumulator with same nonce
//!   │
//!   ▼
//! analyzer.analyze_with_accumulator(Some(builder.accumulator()))
//!   │  └─ For each directory:  acc.record_directory(dir_path)
//!   │  └─ For each file:       acc.record_file(path, bytes, language)
//!   │      └─ Updates rolling SHA-256: hasher.update(file_content_hash)
//!   │      └─ Increments files_read, bytes_read counters
//!   │      └─ Every 100 files: emits a checkpoint with current rolling hash
//!   │
//!   ▼
//! builder.seal(report_json, signing_key)
//!   │  └─ accumulator.finalize() → freezes evidence, records timing/memory
//!   │  └─ serde_json::to_vec(intent) → intent bytes for hashing
//!   │  └─ serde_json::to_vec(evidence) → evidence bytes for hashing
//!   │  └─ ReportSeal::create(nonce, intent_json, evidence_json, report_json)
//!   │      └─ Computes intent_hash, evidence_hash, report_hash
//!   │      └─ chain_hash = SHA-256(intent_hash || evidence_hash || report_hash)
//!   │  └─ seal.sign(key_path)? → Ed25519 over chain_hash (if key provided)
//!   │  └─ A2mlEnvelope::wrap(chain) → sets envelope_type = "trustfile"
//!   │
//!   ▼
//! Writes .attestation.json sidecar alongside the report
//! ```
//!
//! ## Invariants Enforced Here
//!
//! - **INV-3 (Nonce Consistency)**: The nonce generated in `begin()` flows
//!   into both the intent and the accumulator. The seal receives it from
//!   `self.intent.session_nonce`. All three phases get the same value by
//!   construction — not by checking after the fact.
//!
//! - **INV-4 (Temporal Order)**: Intent timestamp is set in `begin()`.
//!   Seal timestamp is set in `seal()`. Since `begin()` is called before
//!   scanning and `seal()` after, temporal ordering holds by the control
//!   flow of the program.
//!
//! - **INV-5 (Chain Hash)**: Computed in `ReportSeal::create()` by hashing
//!   the concatenation of intent_hash, evidence_hash, and report_hash.
//!   This is the cryptographic binding of all three phases.
//!
//! ## Known Gaps
//!
//! - The `expect()` calls in `accumulator()` and `seal()` will panic if
//!   the builder is misused (calling `accumulator()` after `seal()`, or
//!   calling `seal()` twice). This is a programming error, not a runtime
//!   failure — the builder has move semantics (`seal` takes `self`), so
//!   double-seal is prevented at compile time. The `accumulator()` panic
//!   is the only runtime check.

use super::envelope::{A2mlEnvelope, AttestationChain};
use super::evidence::EvidenceAccumulator;
use super::intent::ExecutionIntent;
use super::seal::ReportSeal;
use anyhow::Result;
use std::path::Path;

/// Builder for the three-phase attestation chain.
///
/// This struct holds the state between phases. It is created by `begin()`,
/// populated during scanning via `accumulator()`, and consumed by `seal()`.
///
/// The `accumulator` field is `Option<EvidenceAccumulator>` rather than a
/// bare `EvidenceAccumulator` because `seal()` needs to *take* ownership
/// of it (to call `finalize()`, which consumes the accumulator). Rust's
/// move semantics prevent taking a field out of `&mut self` without
/// `Option::take()`.
///
/// After `seal()` is called, the builder is consumed (moved), so no
/// further operations are possible. This is enforced by the type system:
/// `seal(self, ...)` takes `self` by value, not by reference.
pub struct AttestationChainBuilder {
    /// Phase 1 record: nonce, target hash, tool version, timestamp,
    /// commitment hash. Created once in `begin()` and never modified.
    intent: ExecutionIntent,

    /// Phase 2 accumulator: rolling hash, counters, checkpoints.
    /// `Some` between `begin()` and `seal()`. `None` after `seal()`.
    /// The `Option` wrapper exists solely to allow `take()` in `seal()`.
    accumulator: Option<EvidenceAccumulator>,
}

impl AttestationChainBuilder {
    /// Begin an attestation chain for the given target and CLI arguments.
    ///
    /// This is the entry point. It performs two operations:
    ///
    /// 1. Calls `ExecutionIntent::commit(target, args)`, which:
    ///    - Generates 32 random bytes via `getrandom` crate (CSPRNG)
    ///    - Hex-encodes them to produce the 64-char session nonce
    ///    - Computes SHA-256 of the canonical target path
    ///    - Computes SHA-256 of the tool's own binary (via `/proc/self/exe`)
    ///    - Records the current UTC timestamp in ISO 8601
    ///    - Computes commitment_hash = SHA-256(nonce || target_hash || version || timestamp)
    ///
    /// 2. Creates an `EvidenceAccumulator` initialised with the same nonce.
    ///    The accumulator starts with zeroed counters and an empty SHA-256
    ///    hasher ready to incorporate file content hashes.
    ///
    /// The nonce flows from intent → accumulator by direct string copy.
    /// This is how INV-3 (Nonce Consistency) is satisfied by construction.
    pub fn begin(target: &Path, args: &[String]) -> Result<Self> {
        let intent = ExecutionIntent::commit(target, args)?;
        let accumulator = EvidenceAccumulator::new(&intent.session_nonce);

        Ok(Self {
            intent,
            accumulator: Some(accumulator),
        })
    }

    /// Borrow the evidence accumulator for wiring into the scanner.
    ///
    /// The caller (`main.rs`) passes this mutable reference to the
    /// analyzer, which calls `record_file()` and `record_directory()`
    /// as it processes source files. The accumulator updates its internal
    /// rolling SHA-256 hasher and counters with each call.
    ///
    /// # Panics
    ///
    /// Panics if called after `seal()` — but since `seal()` takes `self`
    /// by value, this can only happen if someone wraps the builder in an
    /// `Option` and calls this after taking it. In normal usage, this
    /// panic is unreachable.
    pub fn accumulator(&mut self) -> &mut EvidenceAccumulator {
        self.accumulator
            .as_mut()
            .expect("accumulator already consumed by seal()")
    }

    /// Finalise the attestation chain and produce the A2ML envelope.
    ///
    /// This method consumes the builder (takes `self` by value) and
    /// performs the following sequence:
    ///
    /// 1. **Finalize evidence**: Calls `accumulator.finalize()`, which
    ///    freezes the rolling hash, records the final wall clock time
    ///    (elapsed since accumulator creation), reads CPU time from
    ///    `/proc/self/stat` (Linux), reads peak RSS from `/proc/self/status`,
    ///    and computes `evidence_hash` = SHA-256 of the serialised evidence.
    ///
    /// 2. **Serialise for hashing**: Converts the intent and evidence
    ///    structs to JSON bytes via `serde_json::to_vec`. These byte
    ///    sequences are what get hashed — the serialised form, not the
    ///    in-memory struct. This means the hash is deterministic: same
    ///    field values → same JSON bytes → same hash.
    ///
    /// 3. **Create seal**: Calls `ReportSeal::create()` with the nonce
    ///    and the three JSON byte slices. The seal computes:
    ///      - `intent_hash`   = SHA-256(intent_json)
    ///      - `evidence_hash` = SHA-256(evidence_json)
    ///      - `report_hash`   = SHA-256(report_json)
    ///      - `chain_hash`    = SHA-256(intent_hash || evidence_hash || report_hash)
    ///    The `||` is string concatenation of the hex digests — 64 + 64 + 64 = 192
    ///    ASCII characters fed into SHA-256.
    ///
    /// 4. **Sign** (optional): If a signing key path is provided, calls
    ///    `seal.sign(key_path)`, which reads the Ed25519 private key seed,
    ///    signs the chain_hash bytes, and stores the signature + public key
    ///    in the seal. This is behind the `signing` feature flag — when
    ///    compiled without it, `sign()` returns an error.
    ///
    /// 5. **Wrap**: Bundles intent + evidence + seal into `AttestationChain`,
    ///    passes to `A2mlEnvelope::wrap()`, which sets `a2ml_version: "1.0.0"`,
    ///    `envelope_type: "trustfile"`, `issuer: "panic-attack/{version}"`,
    ///    `issued_at: now()`, and `decision_hash: seal.report_hash`.
    pub fn seal(
        mut self,
        report_json: &[u8],
        signing_key: Option<&Path>,
    ) -> Result<A2mlEnvelope> {
        // Step 1: Finalise the evidence accumulator.
        // `take()` moves the accumulator out of the Option, leaving None.
        // `finalize()` consumes the accumulator and returns ExecutionEvidence.
        let evidence = self
            .accumulator
            .take()
            .expect("accumulator already consumed")
            .finalize();

        // Step 2: Serialise intent and evidence to deterministic JSON bytes.
        // serde_json::to_vec produces compact JSON (no pretty-printing),
        // which is deterministic for the same field values.
        let intent_json = serde_json::to_vec(&self.intent)?;
        let evidence_json = serde_json::to_vec(&evidence)?;

        // Step 3: Create the seal — computes all four hashes including chain_hash.
        // The nonce is passed directly from self.intent.session_nonce, preserving
        // INV-3 (Nonce Consistency) through the same string reference.
        let mut seal = ReportSeal::create(
            &self.intent.session_nonce,
            &intent_json,
            &evidence_json,
            report_json,
        );

        // Step 4: Optionally sign the chain_hash with Ed25519.
        // The signature covers ONLY chain_hash — since chain_hash binds all
        // three phases, signing it is equivalent to signing the entire chain.
        if let Some(key_path) = signing_key {
            seal.sign(key_path)?;
        }

        // Step 5: Wrap in A2ML envelope with trustfile metadata.
        let chain = AttestationChain {
            intent: self.intent,
            evidence,
            seal,
        };

        Ok(A2mlEnvelope::wrap(chain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_builder_full_lifecycle() {
        let target = PathBuf::from("/tmp");
        let args = vec!["--verbose".to_string()];

        let mut builder = AttestationChainBuilder::begin(&target, &args).unwrap();

        // Simulate scanning
        let acc = builder.accumulator();
        acc.record_directory("/tmp/src");
        acc.record_file("main.rs", b"fn main() {}", "Rust");
        acc.record_file("lib.rs", b"pub mod foo;", "Rust");

        // Seal with a mock report
        let report_json = b"{\"language\":\"Rust\",\"weak_points\":[]}";
        let envelope = builder.seal(report_json, None).unwrap();

        // Verify envelope structure
        assert_eq!(envelope.envelope_type, "trustfile");
        assert_eq!(envelope.attestation.evidence.files_read, 2);
        assert_eq!(
            envelope.attestation.intent.session_nonce,
            envelope.attestation.evidence.session_nonce
        );
        assert_eq!(
            envelope.attestation.intent.session_nonce,
            envelope.attestation.seal.session_nonce
        );
        assert_eq!(
            envelope.decision_hash,
            envelope.attestation.seal.report_hash
        );
    }

    #[test]
    fn test_nonce_consistency_across_phases() {
        let target = PathBuf::from("/tmp");
        let mut builder = AttestationChainBuilder::begin(&target, &[]).unwrap();
        builder.accumulator().record_file("a.rs", b"x", "Rust");

        let envelope = builder.seal(b"{}", None).unwrap();

        let nonce = &envelope.attestation.intent.session_nonce;
        assert_eq!(nonce, &envelope.attestation.evidence.session_nonce);
        assert_eq!(nonce, &envelope.attestation.seal.session_nonce);
    }
}
