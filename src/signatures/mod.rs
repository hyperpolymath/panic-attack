// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Logic-based bug signature detection
//!
//! Inspired by Mozart/Oz logic programming and Datalog inference

pub mod engine;
pub mod rules;

use crate::types::*;

pub use engine::SignatureEngine;

/// Detect bug signatures from crash information
pub fn detect_signatures(crash: &CrashReport) -> Vec<BugSignature> {
    let engine = SignatureEngine::new();
    engine.detect_from_crash(crash)
}
