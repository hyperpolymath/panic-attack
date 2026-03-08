// SPDX-License-Identifier: PMPL-1.0-or-later

//! Assail static analysis module
//!
//! Pre-analyzes target programs to identify weak points and recommend attacks

pub mod analyzer;
pub mod patterns;

use crate::kanren::core::{FactDB, LogicEngine};
use crate::kanren::crosslang::CrossLangAnalyzer;
use crate::kanren::strategy::{self, SearchStrategy};
use crate::kanren::taint::TaintAnalyzer;
use crate::types::*;
use anyhow::Result;
use std::path::Path;

pub use analyzer::Analyzer;

/// Run Assail analysis on a target program
pub fn analyze<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    // Non-verbose mode keeps stdout clean for automation pipelines.
    let analyzer = Analyzer::new(target.as_ref())?;
    analyzer.analyze()
}

/// Run Assail analysis with verbose output including per-file breakdown
/// and miniKanren logic engine results
pub fn analyze_verbose<P: AsRef<Path>>(target: P) -> Result<AssailReport> {
    // Verbose mode is operator-facing and intentionally prints prioritization context.
    let analyzer = Analyzer::new_verbose(target.as_ref())?;
    let report = analyzer.analyze()?;

    println!("Assail Analysis Complete");
    println!("  Language: {:?}", report.language);
    println!("  Frameworks: {:?}", report.frameworks);
    println!("  Weak Points: {}", report.weak_points.len());
    println!("  Recommended Attacks: {:?}", report.recommended_attacks);

    // Per-file breakdown sorted by risk score
    if !report.file_statistics.is_empty() {
        // Use search strategy to determine optimal analysis order
        let strategy = SearchStrategy::auto_select(&report);
        let prioritised = strategy::prioritise_files(&report, strategy);

        println!("\n  Search Strategy: {:?}", strategy);
        println!("  Per-file Breakdown (top 10 by risk):");

        for (rank, file_risk) in prioritised.iter().take(10).enumerate() {
            println!(
                "    {}. {} ({:?}, risk: {:.1})",
                rank + 1,
                file_risk.file_path,
                file_risk.language,
                file_risk.risk_score,
            );
            for factor in &file_risk.risk_factors {
                println!(
                    "       - {}: {:.0} (weight: {:.1})",
                    factor.name, factor.value, factor.weight,
                );
            }
        }

        if prioritised.len() > 10 {
            println!("    ... and {} more files", prioritised.len() - 10);
        }
    }

    // Run miniKanren logic engine for deeper analysis
    run_logic_engine(&report);

    Ok(report)
}

/// Build a fully-populated kanren FactDB from an assail report.
///
/// Ingest all facts (report, taint, cross-language, context) and run
/// forward chaining including FP suppression rules.
/// Returned DB can be used for Logtalk export or further queries.
pub fn build_logic_db(report: &AssailReport) -> FactDB {
    let mut engine = LogicEngine::new();
    engine.ingest_report(report);
    TaintAnalyzer::extract_facts(&mut engine.db, report);
    TaintAnalyzer::load_rules(&mut engine.db);
    CrossLangAnalyzer::extract_facts(&mut engine.db, report);
    CrossLangAnalyzer::load_rules(&mut engine.db);
    engine.extract_context_facts(report);
    engine.load_suppression_rules();
    engine.analyze();
    engine.db
}

/// Run the miniKanren-inspired logic engine on a completed report
fn run_logic_engine(report: &AssailReport) {
    let mut engine = LogicEngine::new();

    // Phase 1: Ingest report facts
    engine.ingest_report(report);

    // Phase 2: Extract taint source/sink facts
    TaintAnalyzer::extract_facts(&mut engine.db, report);
    TaintAnalyzer::load_rules(&mut engine.db);

    // Phase 3: Extract cross-language interaction facts
    CrossLangAnalyzer::extract_facts(&mut engine.db, report);
    CrossLangAnalyzer::load_rules(&mut engine.db);

    // Phase 4: Extract context facts and load FP suppression rules
    engine.extract_context_facts(report);
    engine.load_suppression_rules();

    // Phase 5: Run forward chaining
    let results = engine.analyze();

    println!("\n  Logic Engine Results:");
    println!("    Total facts: {}", results.total_facts);
    println!("    Derived facts: {}", results.derived_facts);
    println!("    Tainted paths: {}", results.tainted_paths);
    println!(
        "    Critical vulnerabilities: {}",
        results.critical_vulnerabilities
    );
    println!("    High vulnerabilities: {}", results.high_vulnerabilities);
    println!("    Cross-language vulns: {}", results.cross_language_vulns);
    if results.suppressed_false_positives > 0 {
        println!(
            "    Suppressed false positives: {}",
            results.suppressed_false_positives
        );
    }

    // Query taint flows
    let flows = TaintAnalyzer::query_flows(&engine.db);
    if !flows.is_empty() {
        println!("\n    Taint Flows ({}):", flows.len());
        for flow in flows.iter().take(10) {
            println!(
                "      {:?} -> {:?} ({} -> {}, confidence: {:.2})",
                flow.source, flow.sink, flow.source_file, flow.sink_file, flow.confidence,
            );
        }
        if flows.len() > 10 {
            println!("      ... and {} more flows", flows.len() - 10);
        }
    }

    // Query cross-language interactions
    let interactions = CrossLangAnalyzer::query_interactions(&engine.db);
    if !interactions.is_empty() {
        println!(
            "\n    Cross-Language Interactions ({}):",
            interactions.len()
        );
        for interaction in interactions.iter().take(10) {
            println!(
                "      {} ({:?}) -> {} ({:?}) via {:?} (risk: {:.2})",
                interaction.caller_file,
                interaction.caller_lang,
                interaction.callee_file,
                interaction.callee_lang,
                interaction.mechanism,
                interaction.risk_score,
            );
        }
        if interactions.len() > 10 {
            println!(
                "      ... and {} more interactions",
                interactions.len() - 10
            );
        }
    }
}
