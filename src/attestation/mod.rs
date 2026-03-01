// SPDX-License-Identifier: PMPL-1.0-or-later

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
