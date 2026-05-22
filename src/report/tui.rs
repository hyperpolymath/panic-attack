// SPDX-License-Identifier: MPL-2.0

//! Lightweight terminal UI for reviewing assault reports

use crate::report::formatter::ReportFormatter;
use crate::types::*;
use anyhow::Result;
use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};
use std::io::{stdout, Write};
use std::time::Duration;

pub struct ReportTui;

impl ReportTui {
    /// Run without a TTY: build all sections and print them as plain text.
    ///
    /// Safe to call in CI, scripts, or any context without a real terminal.
    /// Promotes the tui subcommand from Grade E to Grade D.
    pub fn run_headless(report: &AssaultReport) -> Result<()> {
        let formatter = ReportFormatter::new();
        let sections = Self::build_sections(report, &formatter, true);

        println!("PANIC-ATTACK REPORT REVIEW (headless)");
        println!();

        for section in &sections {
            println!("=== {} ===", section.title);
            println!("{}", section.summary);
            for detail in &section.details {
                println!("  {}", detail);
            }
            println!();
        }

        Ok(())
    }

    pub fn run(report: &AssaultReport) -> Result<()> {
        terminal::enable_raw_mode()?;
        let result = Self::run_inner(report);
        terminal::disable_raw_mode()?;
        result
    }

    fn run_inner(report: &AssaultReport) -> Result<()> {
        let mut stdout = stdout();
        execute!(
            stdout,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;
        let mut selected = 0;
        let mut expanded = Vec::new();
        let mut show_pivot = false;
        let formatter = ReportFormatter::new();

        loop {
            let sections = Self::build_sections(report, &formatter, show_pivot);
            if expanded.len() != sections.len() {
                expanded = vec![false; sections.len()];
                selected = selected.min(sections.len().saturating_sub(1));
            }

            Self::render(&mut stdout, &sections, selected, &expanded)?;

            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(KeyEvent {
                    code, modifiers, ..
                }) = event::read()?
                {
                    match code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => {
                            selected = (selected + 1) % sections.len();
                        }
                        KeyCode::BackTab => {
                            selected = (selected + sections.len() - 1) % sections.len();
                        }
                        KeyCode::Char(' ') => {
                            if let Some(flag) = expanded.get_mut(selected) {
                                *flag = !*flag;
                            }
                        }
                        KeyCode::Char('p') => {
                            show_pivot = !show_pivot;
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            selected = (selected + 1) % sections.len();
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            selected = (selected + sections.len() - 1) % sections.len();
                        }
                        KeyCode::Char('m') if modifiers == KeyModifiers::SHIFT => {
                            show_pivot = !show_pivot;
                        }
                        KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    fn render(
        stdout: &mut impl Write,
        sections: &[Section],
        selected: usize,
        expanded: &[bool],
    ) -> Result<()> {
        execute!(
            stdout,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;
        writeln!(
            stdout,
            "{}",
            "PANIC-ATTACK REPORT REVIEW (TUI)".bold().cyan()
        )?;
        writeln!(stdout)?;

        for (idx, section) in sections.iter().enumerate() {
            let indicator = if idx == selected {
                "➤".green()
            } else {
                "  ".normal()
            };
            writeln!(
                stdout,
                "{} {} {}",
                indicator,
                section.title.bold(),
                section.summary.dimmed()
            )?;
            if expanded.get(idx).copied().unwrap_or(false) {
                for detail in &section.details {
                    writeln!(stdout, "    {}", detail)?;
                }
            }
            writeln!(stdout)?;
        }

        writeln!(
            stdout,
            "{}",
            "Controls: [Tab/j] Next, [Shift+Tab/k] Prev, [Space] Toggle, [p] Pivot, [q] Quit"
                .dimmed()
        )?;
        stdout.flush()?;
        Ok(())
    }

    fn build_sections(
        report: &AssaultReport,
        formatter: &ReportFormatter,
        include_pivot: bool,
    ) -> Vec<Section> {
        let assail = &report.assail_report;
        let mut sections = Vec::new();

        sections.push(Section {
            title: "Assail Summary",
            summary: format!(
                "{} weak points ┃ {} files",
                assail.weak_points.len(),
                assail.file_statistics.len()
            ),
            details: vec![
                format!("Program: {}", assail.program_path.display()),
                format!("Language: {:?}", assail.language),
                format!("Frameworks: {:?}", assail.frameworks),
                format!(
                    "Stats: lines={} unsafe={} panics={} unwraps={}",
                    assail.statistics.total_lines,
                    assail.statistics.unsafe_blocks,
                    assail.statistics.panic_sites,
                    assail.statistics.unwrap_calls
                ),
            ],
        });

        sections.push(Section {
            title: "Core File Risk",
            summary: format!("Top {}", formatter.file_risk_details(assail).len()),
            details: formatter.file_risk_details(assail),
        });

        sections.push(Section {
            title: "Dependencies",
            summary: format!("{} edges", assail.dependency_graph.edges.len()),
            details: formatter.dependency_edges(assail),
        });

        sections.push(Section {
            title: "Taint Matrix",
            summary: format!("{} pivots", assail.taint_matrix.rows.len()),
            details: formatter.taint_matrix_details(assail),
        });

        sections.push(Section {
            title: "Attack Results",
            summary: format!("{} phases", report.attack_results.len()),
            details: report
                .attack_results
                .iter()
                .map(|result| {
                    let status = if result.skipped {
                        "skipped"
                    } else if result.success {
                        "passed"
                    } else {
                        "failed"
                    };
                    let mut line = format!(
                        "{:?}: {} crashes={} (duration {:.2}s)",
                        result.axis,
                        status,
                        result.crashes.len(),
                        result.duration.as_secs_f64()
                    );
                    if result.skipped {
                        if let Some(reason) = &result.skip_reason {
                            line.push_str(&format!("; {}", reason));
                        }
                    }
                    line
                })
                .collect(),
        });

        sections.push(Section {
            title: "Signatures",
            summary: format!("{} detected", report.total_signatures),
            details: report
                .attack_results
                .iter()
                .flat_map(|result| result.signatures_detected.iter())
                .map(|sig| {
                    let location = sig.location.as_deref().unwrap_or("<unknown>").to_string();
                    format!(
                        "{:?} (confidence {:.2}) at {}",
                        sig.signature_type, sig.confidence, location
                    )
                })
                .collect(),
        });

        let mut assessment_notes = Vec::new();
        assessment_notes.extend(report.overall_assessment.critical_issues.iter().cloned());
        assessment_notes.extend(report.overall_assessment.recommendations.iter().cloned());
        sections.push(Section {
            title: "Assessment",
            summary: format!(
                "Score {:.1}/100",
                report.overall_assessment.robustness_score
            ),
            details: assessment_notes,
        });

        if include_pivot {
            let pivot_rows = formatter.pivot_rows(assail);
            sections.push(Section {
                title: "Pivot Matrix",
                summary: format!("{} combos", pivot_rows.len()),
                details: if pivot_rows.is_empty() {
                    vec!["No pivot data available".to_string()]
                } else {
                    pivot_rows
                        .into_iter()
                        .enumerate()
                        .take(4)
                        .map(|(i, (source, axis, severity))| {
                            format!(
                                "{}. {:?} -> {:?} (severity {:.1})",
                                i + 1,
                                source,
                                axis,
                                severity
                            )
                        })
                        .collect()
                },
            });
        }

        sections
    }
}

struct Section {
    title: &'static str,
    summary: String,
    details: Vec<String>,
}
