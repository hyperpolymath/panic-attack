// SPDX-License-Identifier: PMPL-1.0-or-later

//! Report formatting and output

use crate::types::*;
use anyhow::Result;
use clap::ValueEnum;
use colored::*;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum ReportView {
    Summary,
    Accordion,
    Dashboard,
    Matrix,
}

pub struct ReportFormatter;

impl Default for ReportFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn print(&self, report: &AssaultReport) {
        self.print_with_view(report, ReportView::Accordion, false, false);
    }

    pub fn print_with_view(
        &self,
        report: &AssaultReport,
        view: ReportView,
        expand_details: bool,
        show_matrix: bool,
    ) {
        // `view` controls the primary lens; `show_matrix` can append pivot data to non-matrix views.
        println!("\n{}", "=== PANIC-ATTACK ASSAULT REPORT ===".bold().cyan());
        println!();

        let assail = &report.assail_report;

        match view {
            ReportView::Summary => {
                self.print_assail_summary(assail);
                self.print_dependency_overview(assail, false);
                self.print_taint_matrix(assail, false);
            }
            ReportView::Accordion => {
                self.print_assail_summary(assail);
                self.print_accordion_sections(assail, expand_details);
            }
            ReportView::Dashboard => self.print_dashboard(assail),
            ReportView::Matrix => {
                self.print_matrix_view(assail);
            }
        }

        if show_matrix && view != ReportView::Matrix {
            self.print_matrix_view(assail);
        }

        if let Some(timeline) = &report.timeline {
            println!();
            self.print_timeline_summary(timeline);
        }

        println!();
        self.print_attack_summary(&report.attack_results);
        println!();
        self.print_signatures(&report.attack_results);
        println!();
        self.print_overall_assessment(&report.overall_assessment);
        println!();
    }

    #[allow(dead_code)]
    pub fn save<P: AsRef<Path>>(&self, report: &AssaultReport, path: P) -> Result<()> {
        let serialized = serde_json::to_string_pretty(report)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    fn print_assail_summary(&self, scan: &AssailReport) {
        println!("{}", "ASSAIL ANALYSIS".bold().yellow());
        println!("  Program: {}", scan.program_path.display());
        println!("  Language: {:?}", scan.language);
        println!("  Frameworks: {:?}", scan.frameworks);
        println!("  Weak Points: {}", scan.weak_points.len());
        println!();

        println!("  Statistics:");
        println!("    Total lines: {}", scan.statistics.total_lines);
        println!("    Unsafe blocks: {}", scan.statistics.unsafe_blocks);
        println!("    Panic sites: {}", scan.statistics.panic_sites);
        println!("    Unwrap calls: {}", scan.statistics.unwrap_calls);
        println!("    Allocation sites: {}", scan.statistics.allocation_sites);
        println!("    I/O operations: {}", scan.statistics.io_operations);
        println!(
            "    Threading constructs: {}",
            scan.statistics.threading_constructs
        );
        println!();

        if !scan.weak_points.is_empty() {
            println!("  Weak Points Detected: {}", scan.weak_points.len());
            let summary = self.collect_weak_point_summary(scan);
            for (i, line) in summary.iter().enumerate().take(5) {
                println!("    {}. {}", i + 1, line);
            }
            if summary.len() > 5 {
                println!("    ... and {} more weak points", summary.len() - 5);
            }
        }
    }

    fn print_timeline_summary(&self, timeline: &TimelineReport) {
        println!("{}", "TIMELINE".bold().yellow());
        println!("  Duration: {:.2}s", timeline.duration.as_secs_f64());
        println!("  Events: {}", timeline.events.len());
        for event in timeline.events.iter().take(5) {
            let status = if event.ran { "ran" } else { "skipped" };
            println!(
                "    {} [{}] {:?} @ {:.2}s for {:.2}s ({:?})",
                event.id,
                status,
                event.axis,
                event.start_offset.as_secs_f64(),
                event.duration.as_secs_f64(),
                event.intensity
            );
        }
        if timeline.events.len() > 5 {
            println!("    ... and {} more events", timeline.events.len() - 5);
        }
    }

    fn print_accordion_sections(&self, report: &AssailReport, expand_details: bool) {
        println!("{}", "DETAIL PANEL".bold().yellow());
        let sections = self.build_accordion_sections(report);
        for section in sections {
            let marker = if expand_details { "[-]" } else { "[+]" };
            println!("  {} {}", marker, section.title.bold());
            println!("    {}", section.summary);
            if expand_details {
                for detail in section.details {
                    println!("      {}", detail);
                }
            }
            println!();
        }
    }

    fn build_accordion_sections(&self, report: &AssailReport) -> Vec<AccordionSection> {
        vec![
            AccordionSection {
                title: "Core File Risk",
                summary: format!("Top files: {}", report.file_statistics.len()),
                details: self.file_risk_details(report),
            },
            AccordionSection {
                title: "Dependency Graph",
                summary: format!("{} edges", report.dependency_graph.edges.len()),
                details: self.dependency_edges(report),
            },
            AccordionSection {
                title: "Taint Matrix",
                summary: format!("{} pane entries", report.taint_matrix.rows.len()),
                details: self.taint_matrix_details(report),
            },
        ]
    }

    pub(crate) fn file_risk_details(&self, report: &AssailReport) -> Vec<String> {
        let mut scored: Vec<_> = report
            .file_statistics
            .iter()
            .map(|fs| {
                let risk = fs.unsafe_blocks * 3
                    + fs.panic_sites * 2
                    + fs.unwrap_calls
                    + fs.threading_constructs * 2;
                (risk, fs)
            })
            .collect();
        scored.sort_by_key(|(risk, _)| *risk);
        scored
            .into_iter()
            .rev()
            .take(5)
            .map(|(risk, fs)| {
                format!(
                    "{} (risk: {}, unsafe: {}, panics: {}, unwraps: {}, threads: {})",
                    fs.file_path,
                    risk,
                    fs.unsafe_blocks,
                    fs.panic_sites,
                    fs.unwrap_calls,
                    fs.threading_constructs
                )
            })
            .collect()
    }

    pub(crate) fn dependency_edges(&self, report: &AssailReport) -> Vec<String> {
        report
            .dependency_graph
            .edges
            .iter()
            .take(5)
            .map(|edge| {
                format!(
                    "{} -> {} ({}, weight: {:.1})",
                    edge.from, edge.to, edge.relation, edge.weight
                )
            })
            .collect()
    }

    pub(crate) fn taint_matrix_details(&self, report: &AssailReport) -> Vec<String> {
        report
            .taint_matrix
            .rows
            .iter()
            .take(5)
            .map(|row| {
                format!(
                    "{:?} -> {:?} (severity {:.1}, files: {})",
                    row.source_category,
                    row.sink_axis,
                    row.severity_value,
                    row.files.len()
                )
            })
            .collect()
    }

    fn print_dashboard(&self, report: &AssailReport) {
        println!("{}", "DASHBOARD".bold().yellow());
        let max_risk = report
            .file_statistics
            .iter()
            .map(|fs| {
                fs.unsafe_blocks * 3
                    + fs.panic_sites * 2
                    + fs.unwrap_calls
                    + fs.threading_constructs * 2
            })
            .max()
            .unwrap_or(1);

        for fs in report.file_statistics.iter().take(6) {
            let risk = fs.unsafe_blocks * 3
                + fs.panic_sites * 2
                + fs.unwrap_calls
                + fs.threading_constructs * 2;
            let bar = Self::health_bar(risk as f64, max_risk as f64);
            println!(
                "  {} | {} {}",
                fs.file_path.bold(),
                bar,
                format!("risk={}", risk).yellow()
            );
        }

        println!();
        self.print_dependency_overview(report, true);
        self.print_taint_matrix(report, true);
    }

    fn print_matrix_view(&self, report: &AssailReport) {
        println!("{}", "MATRIX / PIVOT".bold().yellow());
        let rows = self.pivot_rows(report);
        if rows.is_empty() {
            println!("  No taint pivots detected");
        } else {
            println!("  Top taint severities:");
            for (i, (source, axis, severity)) in rows.iter().enumerate().take(4) {
                println!(
                    "    {}. {:?} -> {:?} (severity {:.1})",
                    i + 1,
                    source,
                    axis,
                    severity
                );
            }
        }
        println!();
        println!("  Dependency hotspots:");
        for detail in self.dependency_edges(report).iter().take(3) {
            println!("    {}", detail);
        }
    }

    pub(crate) fn pivot_rows(
        &self,
        report: &AssailReport,
    ) -> Vec<(WeakPointCategory, AttackAxis, f64)> {
        let mut aggregate: HashMap<(WeakPointCategory, AttackAxis), f64> = HashMap::new();
        // Aggregate severity by source/sink pair to expose dominant taint channels.
        for row in &report.taint_matrix.rows {
            let key = (row.source_category, row.sink_axis);
            *aggregate.entry(key).or_insert(0.0) += row.severity_value;
        }

        let mut entries: Vec<_> = aggregate
            .into_iter()
            .map(|((source, axis), severity)| (source, axis, severity))
            .collect();
        entries.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        entries
    }

    fn print_dependency_overview(&self, report: &AssailReport, expand: bool) {
        println!("{}", "DEPENDENCIES".bold().yellow());
        println!("  Total edges: {}", report.dependency_graph.edges.len());
        if expand {
            for edge in report.dependency_graph.edges.iter().take(8) {
                println!(
                    "    {} -> {} ({}, {:.1})",
                    edge.from, edge.to, edge.relation, edge.weight
                );
            }
        }
    }

    fn print_taint_matrix(&self, report: &AssailReport, expand: bool) {
        println!("{}", "TAINT MATRIX".bold().yellow());
        if report.taint_matrix.rows.is_empty() {
            println!("  No taint pivots detected");
            return;
        }
        if expand {
            for row in &report.taint_matrix.rows {
                println!(
                    "  [{}] {:?} -> {:?} (severity {:.1}, files: {})",
                    row.relation,
                    row.source_category,
                    row.sink_axis,
                    row.severity_value,
                    row.files.len()
                );
            }
        } else {
            println!(
                "  Top entry: {:?} -> {:?} (severity {:.1})",
                report.taint_matrix.rows[0].source_category,
                report.taint_matrix.rows[0].sink_axis,
                report.taint_matrix.rows[0].severity_value
            );
        }
    }

    fn print_attack_summary(&self, results: &[AttackResult]) {
        println!("{}", "ATTACK RESULTS".bold().yellow());
        for result in results {
            let status = if result.skipped {
                "SKIPPED".yellow()
            } else if result.success {
                "PASSED".green()
            } else {
                "FAILED".red()
            };

            println!(
                "  {:?} attack: {} (exit code: {:?}, duration: {:.2}s)",
                result.axis,
                status,
                result.exit_code,
                result.duration.as_secs_f64()
            );

            if result.skipped {
                if let Some(reason) = &result.skip_reason {
                    println!("    Reason: {}", reason);
                }
                continue;
            }

            if !result.crashes.is_empty() {
                println!(
                    "    Crashes: {}",
                    result.crashes.len().to_string().red().bold()
                );
                for (i, crash) in result.crashes.iter().enumerate() {
                    println!("      {}. Signal: {:?}", i + 1, crash.signal);
                    if let Some(bt) = &crash.backtrace {
                        println!("         Backtrace available: {} bytes", bt.len());
                    }
                }
            }

            if result.peak_memory > 0 {
                println!("    Peak memory: {} MB", result.peak_memory / (1024 * 1024));
            }
        }
    }

    fn print_signatures(&self, results: &[AttackResult]) {
        let total_sigs: usize = results.iter().map(|r| r.signatures_detected.len()).sum();

        if total_sigs > 0 {
            println!("{}", "BUG SIGNATURES DETECTED".bold().red());
            println!("  Total: {}", total_sigs);
            println!();

            for result in results {
                if !result.signatures_detected.is_empty() {
                    println!("  During {:?} attack:", result.axis);
                    for sig in &result.signatures_detected {
                        println!(
                            "    - {:?} (confidence: {:.2})",
                            sig.signature_type, sig.confidence
                        );
                        for evidence in &sig.evidence {
                            println!("      Evidence: {}", evidence.dimmed());
                        }
                        if let Some(loc) = &sig.location {
                            println!("      Location: {}", loc.dimmed());
                        }
                    }
                    println!();
                }
            }
        } else {
            println!("{}", "No bug signatures detected".green());
        }
    }

    fn print_overall_assessment(&self, assessment: &OverallAssessment) {
        println!("{}", "OVERALL ASSESSMENT".bold().yellow());

        let score_color = if assessment.robustness_score >= 80.0 {
            "green"
        } else if assessment.robustness_score >= 50.0 {
            "yellow"
        } else {
            "red"
        };

        println!(
            "  Robustness Score: {}/100",
            format!("{:.1}", assessment.robustness_score)
                .color(score_color)
                .bold()
        );
        println!();

        if !assessment.critical_issues.is_empty() {
            println!("  Critical Issues:");
            for issue in &assessment.critical_issues {
                println!("    - {}", issue);
            }
            println!();
        }

        if !assessment.recommendations.is_empty() {
            println!("  Recommendations:");
            for rec in &assessment.recommendations {
                println!("    - {}", rec);
            }
        }
    }

    fn collect_weak_point_summary(&self, scan: &AssailReport) -> Vec<String> {
        scan.weak_points
            .iter()
            .map(|wp| format!("[{:?}] {}", wp.category, wp.description))
            .collect()
    }

    fn health_bar(value: f64, max: f64) -> String {
        // Unicode bars are used for terminal legibility at a glance.
        let percent = (value / max).clamp(0.0, 1.0);
        let filled = (percent * 20.0).round() as usize;
        let mut bar = String::new();
        for i in 0..20 {
            if i < filled {
                bar.push('█');
            } else {
                bar.push('░');
            }
        }
        bar
    }
}

pub(crate) fn nickel_escape_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{}\"", value))
}

struct AccordionSection {
    title: &'static str,
    summary: String,
    details: Vec<String>,
}
