// SPDX-License-Identifier: MPL-2.0

//! miniKanren-inspired relational logic engine for panic-attack
//!
//! Provides:
//! - **Relational fact database** with unification-based queries
//! - **Taint analysis** tracking data flow from sources to sinks
//! - **Cross-language reasoning** for multi-language codebases
//! - **Search strategies** for prioritising analysis order
//!
//! Inspired by miniKanren (Byrd, Friedman) and Mozart/Oz constraint
//! programming, adapted for static analysis of source code.

pub mod core;
pub mod crosslang;
pub mod strategy;
pub mod taint;

#[allow(unused_imports)]
pub use self::core::{FactDB, LogicEngine};
#[allow(unused_imports)]
pub use crosslang::CrossLangAnalyzer;
#[allow(unused_imports)]
pub use strategy::SearchStrategy;
#[allow(unused_imports)]
pub use taint::{TaintAnalyzer, TaintSink, TaintSource};

// Hypatia integration: panic-attack JSON output is consumed directly by
// Hypatia's Elixir rules engine. The kanren FactDB is used internally for
// taint analysis and cross-language reasoning; Hypatia reads the JSON
// AssailReport (via --output) rather than a separate predicate export.
