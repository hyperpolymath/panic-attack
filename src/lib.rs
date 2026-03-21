// SPDX-License-Identifier: PMPL-1.0-or-later

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
pub mod attestation;
pub mod attack;
pub mod axial;
#[cfg(feature = "http")]
pub mod bridge;
pub mod i18n;
pub mod kanren;
pub mod panll;
pub mod report;
pub mod signatures;
pub mod assemblyline;
pub mod mass_panic;
pub mod notify;
pub mod storage;
pub mod types;
