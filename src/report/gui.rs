// SPDX-License-Identifier: PMPL-1.0-or-later

//! Minimal GUI for reviewing assault reports, system images, and temporal diffs.

use crate::mass_panic::imaging::SystemImage;
use crate::mass_panic::temporal::TemporalDiff;
use crate::report::formatter::ReportFormatter;
use crate::types::{AssaultReport, FileStatistics};
use anyhow::{anyhow, Result};
use eframe::{egui, App, Frame, NativeOptions};

/// Main GUI application state.
///
/// Holds the primary assault report plus optional system image and temporal
/// diff data loaded at runtime via the file path input.
pub struct ReportGui {
    report: AssaultReport,
    tab: ReportTab,
    file_filter: String,
    weak_filter: String,
    attack_filter: String,
    /// Optional system image loaded from JSON.
    system_image: Option<SystemImage>,
    /// Optional temporal diff loaded from JSON.
    temporal_diff: Option<TemporalDiff>,
    /// File path input for loading additional data files.
    load_path: String,
    /// Status message shown after a load attempt.
    load_status: String,
}

/// Navigation tabs for the report viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportTab {
    Summary,
    Assail,
    Matrix,
    Attacks,
    Assessment,
    Image,
    Temporal,
}

impl ReportGui {
    /// Launch the GUI window with the given assault report.
    pub fn run(report: AssaultReport) -> Result<()> {
        let options = NativeOptions::default();
        let app = Self {
            report,
            tab: ReportTab::Summary,
            file_filter: String::new(),
            weak_filter: String::new(),
            attack_filter: String::new(),
            system_image: None,
            temporal_diff: None,
            load_path: String::new(),
            load_status: String::new(),
        };
        eframe::run_native(
            "panic-attack report",
            options,
            Box::new(|_cc| Box::new(app)),
        )
        .map_err(|err| anyhow!("failed to launch report GUI: {err}"))?;
        Ok(())
    }

    /// Attempt to load a JSON file as either an `AssaultReport`, `SystemImage`,
    /// or `TemporalDiff`. Detection is format-based: we try each in turn and
    /// keep the first successful parse.
    fn try_load_file(&mut self) {
        let path = self.load_path.trim();
        if path.is_empty() {
            self.load_status = "No path specified.".to_string();
            return;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) => {
                self.load_status = format!("Read error: {err}");
                return;
            }
        };

        // Try SystemImage first (has "scan_surface" field).
        if let Ok(image) = serde_json::from_str::<SystemImage>(&content) {
            self.system_image = Some(image);
            self.load_status = "Loaded SystemImage.".to_string();
            self.tab = ReportTab::Image;
            return;
        }

        // Try TemporalDiff (has "health_delta" field).
        if let Ok(diff) = serde_json::from_str::<TemporalDiff>(&content) {
            self.temporal_diff = Some(diff);
            self.load_status = "Loaded TemporalDiff.".to_string();
            self.tab = ReportTab::Temporal;
            return;
        }

        // Try AssaultReport.
        if let Ok(report) = serde_json::from_str::<AssaultReport>(&content) {
            self.report = report;
            self.load_status = "Loaded AssaultReport.".to_string();
            self.tab = ReportTab::Summary;
            return;
        }

        self.load_status =
            "Unrecognised format (expected AssaultReport, SystemImage, or TemporalDiff)."
                .to_string();
    }
}

impl App for ReportGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("panic-attack report");
                ui.separator();
                ui.label("Path:");
                let response = ui.text_edit_singleline(&mut self.load_path);
                if ui.button("Load").clicked()
                    || (response.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    self.try_load_file();
                }
                if !self.load_status.is_empty() {
                    ui.label(&self.load_status);
                }
            });
        });

        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.selectable_value(&mut self.tab, ReportTab::Summary, "Summary");
            ui.selectable_value(&mut self.tab, ReportTab::Assail, "Assail");
            ui.selectable_value(&mut self.tab, ReportTab::Matrix, "Matrix");
            ui.selectable_value(&mut self.tab, ReportTab::Attacks, "Attacks");
            ui.selectable_value(&mut self.tab, ReportTab::Assessment, "Assessment");
            ui.separator();
            let image_label = if self.system_image.is_some() {
                "Image"
            } else {
                "Image (empty)"
            };
            ui.selectable_value(&mut self.tab, ReportTab::Image, image_label);
            let temporal_label = if self.temporal_diff.is_some() {
                "Temporal"
            } else {
                "Temporal (empty)"
            };
            ui.selectable_value(&mut self.tab, ReportTab::Temporal, temporal_label);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            ReportTab::Summary => self.render_summary(ui),
            ReportTab::Assail => self.render_assail(ui),
            ReportTab::Matrix => self.render_matrix(ui),
            ReportTab::Attacks => self.render_attacks(ui),
            ReportTab::Assessment => self.render_assessment(ui),
            ReportTab::Image => self.render_image(ui),
            ReportTab::Temporal => self.render_temporal(ui),
        });
    }
}

// ---------------------------------------------------------------------------
// Existing tab renderers (unchanged)
// ---------------------------------------------------------------------------

impl ReportGui {
    fn render_summary(&self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Summary");
        ui.label(format!("Program: {}", assail.program_path.display()));
        ui.label(format!("Language: {:?}", assail.language));
        ui.label(format!("Frameworks: {:?}", assail.frameworks));
        ui.label(format!("Weak points: {}", assail.weak_points.len()));
        ui.label(format!("Total crashes: {}", self.report.total_crashes));
        ui.label(format!(
            "Total signatures: {}",
            self.report.total_signatures
        ));
        let (passed, failed, skipped) = count_attack_status(&self.report.attack_results);
        ui.label(format!(
            "Attack outcomes: passed={} failed={} skipped={}",
            passed, failed, skipped
        ));
    }

    fn render_assail(&mut self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Assail details");
        ui.label(format!(
            "Stats: lines={} unsafe={} panics={} unwraps={}",
            assail.statistics.total_lines,
            assail.statistics.unsafe_blocks,
            assail.statistics.panic_sites,
            assail.statistics.unwrap_calls
        ));
        ui.separator();

        ui.heading("File risk");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.file_filter);
        });
        let mut files: Vec<&FileStatistics> = assail.file_statistics.iter().collect();
        files.sort_by_key(|fs| file_risk(fs));
        files.reverse();
        egui::Grid::new("file-risk").striped(true).show(ui, |ui| {
            ui.label("File");
            ui.label("Risk");
            ui.label("Unsafe");
            ui.label("Panics");
            ui.label("Unwraps");
            ui.end_row();
            for fs in files.iter().take(50) {
                if !self.file_filter.trim().is_empty()
                    && !fs
                        .file_path
                        .to_lowercase()
                        .contains(&self.file_filter.to_lowercase())
                {
                    continue;
                }
                let risk = file_risk(fs);
                ui.label(&fs.file_path);
                ui.label(risk.to_string());
                ui.label(fs.unsafe_blocks.to_string());
                ui.label(fs.panic_sites.to_string());
                ui.label(fs.unwrap_calls.to_string());
                ui.end_row();
            }
        });

        ui.separator();
        ui.heading("Weak points");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.weak_filter);
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            for wp in &assail.weak_points {
                let desc = wp.description.trim();
                let match_filter = self.weak_filter.trim().is_empty()
                    || desc
                        .to_lowercase()
                        .contains(&self.weak_filter.to_lowercase())
                    || format!("{:?}", wp.category)
                        .to_lowercase()
                        .contains(&self.weak_filter.to_lowercase());
                if match_filter {
                    ui.label(format!("[{:?}] {}", wp.category, desc));
                }
            }
        });

        ui.separator();
        ui.collapsing("Dependencies", |ui| {
            for edge in assail.dependency_graph.edges.iter().take(40) {
                ui.label(format!(
                    "{} -> {} ({}, weight {:.1})",
                    edge.from, edge.to, edge.relation, edge.weight
                ));
            }
        });
    }

    fn render_matrix(&self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Matrix view");
        let formatter = ReportFormatter::new();
        let pivots = formatter.pivot_rows(assail);
        ui.label(format!("Pivot rows: {}", pivots.len()));
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (source, axis, severity) in pivots.iter().take(40) {
                ui.label(format!(
                    "{:?} -> {:?} (severity {:.1})",
                    source, axis, severity
                ));
            }
        });
        ui.separator();
        ui.heading("Taint matrix rows");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in assail.taint_matrix.rows.iter().take(60) {
                ui.label(format!(
                    "{:?} -> {:?} (severity {:.1}, files {})",
                    row.source_category,
                    row.sink_axis,
                    row.severity_value,
                    row.files.len()
                ));
            }
        });
    }

    fn render_attacks(&mut self, ui: &mut egui::Ui) {
        ui.heading("Attack results");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.attack_filter);
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            for result in &self.report.attack_results {
                let status = if result.skipped {
                    "skipped"
                } else if result.success {
                    "passed"
                } else {
                    "failed"
                };
                let label = format!(
                    "{:?}: {} (exit {:?}, crashes {})",
                    result.axis,
                    status,
                    result.exit_code,
                    result.crashes.len()
                );
                if !self.attack_filter.trim().is_empty()
                    && !label
                        .to_lowercase()
                        .contains(&self.attack_filter.to_lowercase())
                {
                    continue;
                }
                ui.label(label);
                if let Some(reason) = &result.skip_reason {
                    ui.label(format!("  reason: {}", reason));
                }
            }
        });
    }

    fn render_assessment(&self, ui: &mut egui::Ui) {
        let assessment = &self.report.overall_assessment;
        ui.heading("Overall assessment");
        ui.label(format!(
            "Robustness score: {:.1}/100",
            assessment.robustness_score
        ));
        if !assessment.critical_issues.is_empty() {
            ui.separator();
            ui.label("Critical issues:");
            for issue in &assessment.critical_issues {
                ui.label(format!("- {}", issue));
            }
        }
        if !assessment.recommendations.is_empty() {
            ui.separator();
            ui.label("Recommendations:");
            for rec in &assessment.recommendations {
                ui.label(format!("- {}", rec));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// New tab renderers: SystemImage and TemporalDiff
// ---------------------------------------------------------------------------

impl ReportGui {
    /// Render the SystemImage viewer tab.
    fn render_image(&self, ui: &mut egui::Ui) {
        let image = match &self.system_image {
            Some(img) => img,
            None => {
                ui.heading("System Image");
                ui.label("No system image loaded. Use the path input above to load a JSON file.");
                return;
            }
        };

        ui.heading("System Image");
        ui.label(format!("Scan surface: {}", image.scan_surface));
        ui.label(format!("Generated: {}", image.generated_at));
        ui.label(format!(
            "Nodes: {}  Edges: {}  Repos scanned: {}",
            image.node_count, image.edge_count, image.repos_scanned
        ));
        ui.label(format!(
            "Files: {}  Lines: {}",
            image.total_files, image.total_lines
        ));

        ui.separator();

        // Global health and risk as colored labels.
        ui.horizontal(|ui| {
            ui.label("Global health:");
            let health_color = health_color(image.global_health);
            ui.colored_label(health_color, format!("{:.1}%", image.global_health * 100.0));
            ui.add_space(16.0);
            ui.label("Global risk:");
            let risk_color = risk_color(image.global_risk);
            ui.colored_label(risk_color, format!("{:.1}%", image.global_risk * 100.0));
        });

        ui.horizontal(|ui| {
            ui.label(format!("Weak points: {}", image.total_weak_points));
            ui.add_space(8.0);
            ui.label(format!("Critical: {}", image.total_critical));
        });

        ui.separator();

        // Risk distribution bar.
        ui.heading("Risk distribution");
        let dist = &image.risk_distribution;
        let total = dist.healthy + dist.low + dist.moderate + dist.high + dist.critical;
        if total > 0 {
            ui.horizontal(|ui| {
                risk_bar_segment(ui, "Healthy", dist.healthy, total, COLOUR_GREEN);
                risk_bar_segment(ui, "Low", dist.low, total, COLOUR_LIME);
                risk_bar_segment(ui, "Moderate", dist.moderate, total, COLOUR_YELLOW);
                risk_bar_segment(ui, "High", dist.high, total, COLOUR_ORANGE);
                risk_bar_segment(ui, "Critical", dist.critical, total, COLOUR_RED);
            });
        } else {
            ui.label("No nodes measured.");
        }

        ui.separator();

        // Node list sorted by risk (highest first).
        ui.heading("Nodes (sorted by risk)");
        let mut sorted_nodes: Vec<&crate::mass_panic::imaging::ImageNode> =
            image.nodes.iter().collect();
        sorted_nodes.sort_by(|a, b| {
            b.risk_intensity
                .partial_cmp(&a.risk_intensity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("image-nodes")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.label("Health");
                    ui.label("Risk");
                    ui.label("Weak pts");
                    ui.label("Critical");
                    ui.label("Files");
                    ui.label("Lines");
                    ui.end_row();
                    for node in &sorted_nodes {
                        ui.label(&node.name);
                        let hc = health_color(node.health_score);
                        ui.colored_label(hc, format!("{:.0}%", node.health_score * 100.0));
                        let rc = risk_color(node.risk_intensity);
                        ui.colored_label(rc, format!("{:.0}%", node.risk_intensity * 100.0));
                        ui.label(node.weak_point_count.to_string());
                        ui.label(node.critical_count.to_string());
                        ui.label(node.total_files.to_string());
                        ui.label(node.total_lines.to_string());
                        ui.end_row();
                    }
                });
        });
    }

    /// Render the TemporalDiff viewer tab.
    fn render_temporal(&self, ui: &mut egui::Ui) {
        let diff = match &self.temporal_diff {
            Some(d) => d,
            None => {
                ui.heading("Temporal Diff");
                ui.label(
                    "No temporal diff loaded. Use the path input above to load a JSON file.",
                );
                return;
            }
        };

        ui.heading("Temporal Diff");

        // Timestamps and labels.
        ui.label(format!(
            "From: {} {}",
            diff.from_timestamp,
            if diff.from_label.is_empty() {
                String::new()
            } else {
                format!("({})", diff.from_label)
            }
        ));
        ui.label(format!(
            "To:   {} {}",
            diff.to_timestamp,
            if diff.to_label.is_empty() {
                String::new()
            } else {
                format!("({})", diff.to_label)
            }
        ));

        ui.separator();

        // Trend as a colored label.
        ui.horizontal(|ui| {
            ui.label("Trend:");
            let (trend_text, trend_color) = match diff.trend {
                crate::mass_panic::temporal::Trend::Improving => ("Improving", COLOUR_GREEN),
                crate::mass_panic::temporal::Trend::Degrading => ("Degrading", COLOUR_RED),
                crate::mass_panic::temporal::Trend::Stable => ("Stable", COLOUR_LIME),
                crate::mass_panic::temporal::Trend::Mixed => ("Mixed", COLOUR_YELLOW),
            };
            ui.colored_label(trend_color, trend_text);
        });

        ui.separator();

        // Deltas.
        ui.heading("Deltas");
        ui.horizontal(|ui| {
            ui.label("Health delta:");
            let hc = if diff.health_delta > 0.0 {
                COLOUR_GREEN
            } else if diff.health_delta < 0.0 {
                COLOUR_RED
            } else {
                COLOUR_GREY
            };
            ui.colored_label(hc, format!("{:+.3}", diff.health_delta));
        });
        ui.horizontal(|ui| {
            ui.label("Risk delta:");
            // Negative risk delta is good (less risk).
            let rc = if diff.risk_delta < 0.0 {
                COLOUR_GREEN
            } else if diff.risk_delta > 0.0 {
                COLOUR_RED
            } else {
                COLOUR_GREY
            };
            ui.colored_label(rc, format!("{:+.3}", diff.risk_delta));
        });
        ui.horizontal(|ui| {
            ui.label("Weak point delta:");
            let wc = if diff.weak_point_delta < 0 {
                COLOUR_GREEN
            } else if diff.weak_point_delta > 0 {
                COLOUR_RED
            } else {
                COLOUR_GREY
            };
            ui.colored_label(wc, format!("{:+}", diff.weak_point_delta));
        });
        ui.horizontal(|ui| {
            ui.label("Critical delta:");
            let cc = if diff.critical_delta < 0 {
                COLOUR_GREEN
            } else if diff.critical_delta > 0 {
                COLOUR_RED
            } else {
                COLOUR_GREY
            };
            ui.colored_label(cc, format!("{:+}", diff.critical_delta));
        });

        ui.label(format!("Unchanged nodes: {}", diff.unchanged_count));

        ui.separator();

        // New and removed nodes.
        if !diff.new_nodes.is_empty() {
            ui.collapsing(
                format!("New nodes ({})", diff.new_nodes.len()),
                |ui| {
                    for node_id in &diff.new_nodes {
                        ui.colored_label(COLOUR_GREEN, node_id);
                    }
                },
            );
        }

        if !diff.removed_nodes.is_empty() {
            ui.collapsing(
                format!("Removed nodes ({})", diff.removed_nodes.len()),
                |ui| {
                    for node_id in &diff.removed_nodes {
                        ui.colored_label(COLOUR_RED, node_id);
                    }
                },
            );
        }

        ui.separator();

        // Improved nodes.
        if !diff.improved_nodes.is_empty() {
            ui.heading(format!("Improved nodes ({})", diff.improved_nodes.len()));
            egui::ScrollArea::vertical()
                .id_source("improved-scroll")
                .max_height(200.0)
                .show(ui, |ui| {
                    egui::Grid::new("improved-nodes")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.label("Health before");
                            ui.label("Health after");
                            ui.label("Risk before");
                            ui.label("Risk after");
                            ui.end_row();
                            for nd in &diff.improved_nodes {
                                ui.label(&nd.name);
                                ui.colored_label(
                                    health_color(nd.health_before),
                                    format!("{:.0}%", nd.health_before * 100.0),
                                );
                                ui.colored_label(
                                    health_color(nd.health_after),
                                    format!("{:.0}%", nd.health_after * 100.0),
                                );
                                ui.colored_label(
                                    risk_color(nd.risk_before),
                                    format!("{:.0}%", nd.risk_before * 100.0),
                                );
                                ui.colored_label(
                                    risk_color(nd.risk_after),
                                    format!("{:.0}%", nd.risk_after * 100.0),
                                );
                                ui.end_row();
                            }
                        });
                });
        }

        // Degraded nodes.
        if !diff.degraded_nodes.is_empty() {
            ui.heading(format!("Degraded nodes ({})", diff.degraded_nodes.len()));
            egui::ScrollArea::vertical()
                .id_source("degraded-scroll")
                .max_height(200.0)
                .show(ui, |ui| {
                    egui::Grid::new("degraded-nodes")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.label("Health before");
                            ui.label("Health after");
                            ui.label("Risk before");
                            ui.label("Risk after");
                            ui.end_row();
                            for nd in &diff.degraded_nodes {
                                ui.label(&nd.name);
                                ui.colored_label(
                                    health_color(nd.health_before),
                                    format!("{:.0}%", nd.health_before * 100.0),
                                );
                                ui.colored_label(
                                    health_color(nd.health_after),
                                    format!("{:.0}%", nd.health_after * 100.0),
                                );
                                ui.colored_label(
                                    risk_color(nd.risk_before),
                                    format!("{:.0}%", nd.risk_before * 100.0),
                                );
                                ui.colored_label(
                                    risk_color(nd.risk_after),
                                    format!("{:.0}%", nd.risk_after * 100.0),
                                );
                                ui.end_row();
                            }
                        });
                });
        }
    }
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

/// Green for healthy scores.
const COLOUR_GREEN: egui::Color32 = egui::Color32::from_rgb(0, 200, 80);
/// Lime for low-risk / stable.
const COLOUR_LIME: egui::Color32 = egui::Color32::from_rgb(160, 220, 0);
/// Yellow for moderate risk.
const COLOUR_YELLOW: egui::Color32 = egui::Color32::from_rgb(240, 200, 0);
/// Orange for high risk.
const COLOUR_ORANGE: egui::Color32 = egui::Color32::from_rgb(240, 130, 0);
/// Red for critical risk.
const COLOUR_RED: egui::Color32 = egui::Color32::from_rgb(220, 40, 40);
/// Grey for neutral / zero deltas.
const COLOUR_GREY: egui::Color32 = egui::Color32::from_rgb(160, 160, 160);

/// Map a health score (0.0 = critical, 1.0 = healthy) to a colour.
fn health_color(health: f64) -> egui::Color32 {
    if health >= 0.8 {
        COLOUR_GREEN
    } else if health >= 0.6 {
        COLOUR_LIME
    } else if health >= 0.4 {
        COLOUR_YELLOW
    } else if health >= 0.2 {
        COLOUR_ORANGE
    } else {
        COLOUR_RED
    }
}

/// Map a risk intensity (0.0 = safe, 1.0 = critical) to a colour.
fn risk_color(risk: f64) -> egui::Color32 {
    if risk < 0.2 {
        COLOUR_GREEN
    } else if risk < 0.4 {
        COLOUR_LIME
    } else if risk < 0.6 {
        COLOUR_YELLOW
    } else if risk < 0.8 {
        COLOUR_ORANGE
    } else {
        COLOUR_RED
    }
}

/// Render a single segment of the risk distribution bar with a label.
fn risk_bar_segment(
    ui: &mut egui::Ui,
    label: &str,
    count: usize,
    total: usize,
    colour: egui::Color32,
) {
    if count == 0 {
        return;
    }
    let pct = (count as f64 / total as f64) * 100.0;
    ui.colored_label(colour, format!("{label}: {count} ({pct:.0}%)"));
    ui.add_space(4.0);
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

/// Compute a simple file risk score from static analysis counts.
fn file_risk(fs: &FileStatistics) -> usize {
    fs.unsafe_blocks * 3 + fs.panic_sites * 2 + fs.unwrap_calls + fs.threading_constructs * 2
}

/// Count attack result statuses: (passed, failed, skipped).
fn count_attack_status(results: &[crate::types::AttackResult]) -> (usize, usize, usize) {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for result in results {
        if result.skipped {
            skipped += 1;
        } else if result.success {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    (passed, failed, skipped)
}
