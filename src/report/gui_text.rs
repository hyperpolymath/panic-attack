// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Headless GUI report renderer — text-only output, no display server.
//!
//! This is the `gui --headless` path. It is always compiled (independent of the
//! `gui` feature flag) so the readiness test `readiness_d_gui_headless_runs`
//! and CI integrations keep working in MSRV-clean default builds. The
//! windowed renderer in [`crate::report::gui`] is feature-gated because eframe
//! raises MSRV above 1.85.0.

use crate::report::formatter::ReportFormatter;
use crate::types::AssaultReport;
use anyhow::Result;

/// Print a structured text summary of every GUI panel.
///
/// Safe to call in CI or headless environments with no Wayland/X11 display.
/// Promotes the `gui` subcommand from Grade E to Grade D.
pub fn run_headless(report: AssaultReport) -> Result<()> {
    let assail = &report.assail_report;
    let formatter = ReportFormatter::new();

    println!("PANIC-ATTACK GUI REPORT (headless)");
    println!();

    println!("=== Summary ===");
    println!("Language: {:?}", assail.language);
    println!(
        "Score: {:.1}/100",
        report.overall_assessment.robustness_score
    );
    println!("Crashes: {}", report.total_crashes);
    println!("Signatures: {}", report.total_signatures);
    println!("Weak points: {}", assail.weak_points.len());
    println!("Frameworks: {:?}", assail.frameworks);
    println!();

    println!("=== Assail ===");
    println!("Program: {}", assail.program_path.display());
    println!(
        "Stats: lines={} unsafe={} panics={} unwraps={}",
        assail.statistics.total_lines,
        assail.statistics.unsafe_blocks,
        assail.statistics.panic_sites,
        assail.statistics.unwrap_calls
    );
    for wp in &assail.weak_points {
        let loc = wp
            .location
            .as_deref()
            .or(wp.file.as_deref())
            .unwrap_or("<unknown>");
        println!(
            "  [{:?}] {:?} @ {} — {}",
            wp.severity, wp.category, loc, wp.description
        );
    }
    println!();

    println!("=== File Risk ===");
    for detail in formatter.file_risk_details(assail) {
        println!("  {}", detail);
    }
    println!();

    println!("=== Matrix ===");
    println!(
        "Dependency edges: {}  Taint rows: {}",
        assail.dependency_graph.edges.len(),
        assail.taint_matrix.rows.len()
    );
    for detail in formatter.taint_matrix_details(assail) {
        println!("  {}", detail);
    }
    println!();

    println!("=== Attacks ===");
    for result in &report.attack_results {
        let status = if result.skipped {
            "skipped"
        } else if result.success {
            "passed"
        } else {
            "failed"
        };
        println!(
            "  {:?}: {} crashes={} duration={:.2}s",
            result.axis,
            status,
            result.crashes.len(),
            result.duration.as_secs_f64()
        );
    }
    println!();

    println!("=== Assessment ===");
    for issue in &report.overall_assessment.critical_issues {
        println!("  CRITICAL: {}", issue);
    }
    for rec in &report.overall_assessment.recommendations {
        println!("  REC: {}", rec);
    }
    println!();

    Ok(())
}
