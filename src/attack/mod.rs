// SPDX-License-Identifier: MPL-2.0

//! Attack orchestration module

pub mod executor;
pub mod profile;
pub mod strategies;

use crate::types::*;
use anyhow::Result;

pub use executor::AttackExecutor;
pub use profile::AttackProfile;

/// Execute an attack against a target program
pub fn execute_attack(config: AttackConfig) -> Result<Vec<AttackResult>> {
    // Thin wrapper keeps CLI and library callers on the same execution surface.
    let executor = AttackExecutor::new(config);
    executor.execute()
}

/// Execute an attack with pattern-aware strategy selection
pub fn execute_attack_with_patterns(
    config: AttackConfig,
    language: Language,
    frameworks: &[Framework],
) -> Result<Vec<AttackResult>> {
    // Pattern-aware mode enriches axis execution with language/framework heuristics.
    let executor = AttackExecutor::with_patterns(config, language, frameworks);
    executor.execute()
}
