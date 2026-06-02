// SPDX-License-Identifier: MPL-2.0

//! Panic-Attacker — Universal Stress Testing & Bug Signature Detection.
//!
//! This crate provides the core engine for "Security Ambush" operations.
//! It combines traditional stress testing (chaos engineering) with
//! logic-based inference to identify subtle race conditions and
//! state-corruption bugs.
//!
//! ENGINE PILLARS:
//! 1. **Ambush**: Orchestrates high-concurrency attack patterns.
//! 2. **Kanren**: Employs relational programming (microKanren) to infer
//!    logical contradictions from system logs.
//! 3. **Signatures**: A database of known bug patterns (e.g. "Double Free",
//!    "UAF", "Logic Contradiction") matched against execution traces.

pub mod a2ml;
pub mod abduct;
pub mod adjudicate;
pub mod ambush;
pub mod amuck;
pub mod assail;
pub mod assemblyline;
pub mod attack;
pub mod attestation;
pub mod axial;
#[cfg(feature = "http")]
pub mod bridge;
pub mod campaign;
pub mod comment_marker;
pub mod ffi_kind;
pub mod i18n;
pub mod jit_context;
pub mod kanren;
pub mod mass_panic;
pub mod notify;
pub mod panll;
pub mod query;
pub mod report;
pub mod signatures;
pub mod storage;
pub mod sweep_tracker;
pub mod test_context;
pub mod types;
