// SPDX-License-Identifier: MPL-2.0

//! Report generation module

pub mod diff;
pub mod formatter;
pub mod generator;
pub mod gui;
pub mod migration;
pub mod output;
pub mod sarif;
pub mod tui;

use crate::types::*;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub use diff::{format_diff, load_report};
pub use formatter::{ReportFormatter, ReportView};
pub use generator::ReportGenerator;
pub use gui::ReportGui;
pub use output::ReportOutputFormat;
pub use tui::ReportTui;

/// Generate a comprehensive assault report
pub fn generate_assault_report(
    assail_report: AssailReport,
    attack_results: Vec<AttackResult>,
) -> Result<AssaultReport> {
    // Centralize report construction so scoring logic stays in one module.
    let generator = ReportGenerator::new();
    generator.generate(assail_report, attack_results)
}

/// Save report to file with the requested format
pub fn save_report<P: AsRef<Path>>(
    report: &AssaultReport,
    path: P,
    format: ReportOutputFormat,
) -> Result<()> {
    // Output format selection is delegated to the formatter enum for consistency.
    let serialized = format.serialize(report)?;
    fs::write(path, serialized)?;
    Ok(())
}

/// Print report to console with view/depth controls
pub fn print_report(
    report: &AssaultReport,
    view: ReportView,
    expand_details: bool,
    show_matrix: bool,
) {
    // Console rendering always flows through ReportFormatter view contracts.
    let formatter = ReportFormatter::new();
    formatter.print_with_view(report, view, expand_details, show_matrix);
}
