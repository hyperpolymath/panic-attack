// SPDX-License-Identifier: PMPL-1.0-or-later

//! PanLL export helpers.
//!
//! Three export formats for panic-attack → PanLL integration:
//!
//! 1. **Event chain** (`panll.event-chain.v0`) — single-program stress test
//!    results with attack events, constraints, and timeline. Maps to Pane-W
//!    event chain viewer.
//!
//! 2. **System image** (`panll.system-image.v0`) — fNIRS-style spatial health
//!    map from assemblyline/mass-panic scans. Maps to a dedicated imaging
//!    panel with risk heatmap, node graph, and risk distribution.
//!
//! 3. **Temporal diff** (`panll.temporal-diff.v0`) — time-series comparison
//!    between two system image snapshots. Maps to a temporal navigation
//!    panel with trend arrows, health delta bars, and node-level changes.

use crate::mass_panic::imaging::SystemImage;
use crate::mass_panic::temporal::TemporalDiff;
use crate::types::{AssaultReport, AttackAxis, Severity, WeakPointCategory};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
struct PanllExport {
    format: String,
    generated_at: String,
    source: PanllSource,
    summary: PanllSummary,
    timeline: Option<PanllTimeline>,
    event_chain: Vec<PanllEvent>,
    constraints: Vec<PanllConstraint>,
}

#[derive(Debug, Serialize)]
struct PanllSource {
    tool: String,
    report_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct PanllSummary {
    program: String,
    weak_points: usize,
    critical_weak_points: usize,
    total_crashes: usize,
    robustness_score: f64,
}

#[derive(Debug, Serialize)]
struct PanllTimeline {
    duration_ms: u64,
    events: usize,
}

#[derive(Debug, Serialize)]
struct PanllEvent {
    id: String,
    axis: String,
    start_ms: Option<u64>,
    duration_ms: u64,
    intensity: String,
    status: String,
    peak_memory: Option<u64>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct PanllConstraint {
    id: String,
    description: String,
}

fn export_report(report: &AssaultReport, report_path: Option<&Path>) -> PanllExport {
    let timeline = report.timeline.as_ref().map(|timeline| PanllTimeline {
        duration_ms: timeline.duration.as_millis() as u64,
        events: timeline.events.len(),
    });

    let mut event_chain = Vec::new();
    if let Some(timeline) = &report.timeline {
        for event in &timeline.events {
            let status = if event.ran { "ran" } else { "skipped" };
            event_chain.push(PanllEvent {
                id: event.id.clone(),
                axis: axis_label(event.axis),
                start_ms: Some(event.start_offset.as_millis() as u64),
                duration_ms: event.duration.as_millis() as u64,
                intensity: format!("{:?}", event.intensity),
                status: status.to_string(),
                peak_memory: event.peak_memory,
                notes: None,
            });
        }
    } else {
        for (index, result) in report.attack_results.iter().enumerate() {
            let status = if result.skipped {
                "skipped"
            } else if result.success {
                "passed"
            } else {
                "failed"
            };
            event_chain.push(PanllEvent {
                id: format!("attack-{}-{}", axis_label(result.axis), index + 1),
                axis: axis_label(result.axis),
                start_ms: None,
                duration_ms: result.duration.as_millis() as u64,
                intensity: "unknown".to_string(),
                status: status.to_string(),
                peak_memory: Some(result.peak_memory),
                notes: result.skip_reason.clone(),
            });
        }
    }

    let critical_weak_points = report
        .assail_report
        .weak_points
        .iter()
        .filter(|wp| wp.severity == Severity::Critical)
        .count();

    // Extract constraints from findings — critical weak points, taint paths,
    // and cross-language boundary risks become Pane-L constraints in PanLL.
    let constraints = extract_constraints(report);

    PanllExport {
        format: "panll.event-chain.v0".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        source: PanllSource {
            tool: "panic-attack".to_string(),
            report_path: report_path.map(|path| path.display().to_string()),
        },
        summary: PanllSummary {
            program: report.assail_report.program_path.display().to_string(),
            weak_points: report.assail_report.weak_points.len(),
            critical_weak_points,
            total_crashes: report.total_crashes,
            robustness_score: report.overall_assessment.robustness_score,
        },
        timeline,
        event_chain,
        constraints,
    }
}

pub fn write_export(
    report: &AssaultReport,
    report_path: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let export = export_report(report, report_path);
    let json = serde_json::to_string_pretty(&export)?;
    fs::write(output, json)
        .with_context(|| format!("writing panll export {}", output.display()))?;
    Ok(())
}

/// Extract Pane-L constraints from the assault report.
///
/// Constraints represent invariants that PanLL's symbolic mass (Pane-L) should
/// track and enforce. They come from:
/// - Critical weak points (must-fix findings)
/// - Taint matrix paths (source-to-sink data flows)
/// - Failed attack axes (stress test failures)
/// - Critical issues from overall assessment
fn extract_constraints(report: &AssaultReport) -> Vec<PanllConstraint> {
    let mut constraints = Vec::new();
    let mut id_counter = 0usize;

    // Constraint from each critical weak point
    for wp in &report.assail_report.weak_points {
        if wp.severity == Severity::Critical {
            id_counter += 1;
            let location = wp
                .location
                .as_deref()
                .unwrap_or("unknown");
            constraints.push(PanllConstraint {
                id: format!("wp-crit-{}", id_counter),
                description: format!(
                    "[{}] {} at {}",
                    category_label(wp.category),
                    wp.description,
                    location
                ),
            });
        }
    }

    // Constraints from taint matrix — high-severity source-to-sink paths
    for row in &report.assail_report.taint_matrix.rows {
        if row.severity_value >= 7.0 {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("taint-{}", id_counter),
                description: format!(
                    "Taint flow: {:?} -> {:?} (severity {:.1}) across {} files",
                    row.source_category,
                    row.sink_axis,
                    row.severity_value,
                    row.files.len()
                ),
            });
        }
    }

    // Constraints from failed attack axes
    for result in &report.attack_results {
        if !result.success && !result.skipped {
            id_counter += 1;
            let crash_count = result.crashes.len();
            constraints.push(PanllConstraint {
                id: format!("attack-fail-{}", id_counter),
                description: format!(
                    "Failed {} stress test: {} crashes, {} signatures detected",
                    axis_label(result.axis),
                    crash_count,
                    result.signatures_detected.len()
                ),
            });
        }
    }

    // Constraints from critical issues in overall assessment
    for issue in &report.overall_assessment.critical_issues {
        id_counter += 1;
        constraints.push(PanllConstraint {
            id: format!("critical-{}", id_counter),
            description: issue.clone(),
        });
    }

    // Migration-specific constraints (when ReScript migration metrics are present)
    if let Some(ref metrics) = report.assail_report.migration_metrics {
        if metrics.deprecated_api_count > 0 {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("migration-deprecated-{}", id_counter),
                description: format!(
                    "{} deprecated Js.*/Belt.* API calls remaining (health: {:.0}%)",
                    metrics.deprecated_api_count,
                    metrics.health_score * 100.0
                ),
            });
        }

        if matches!(
            metrics.config_format,
            crate::types::ReScriptConfigFormat::BsConfig
                | crate::types::ReScriptConfigFormat::Both
        ) {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("migration-config-{}", id_counter),
                description: format!(
                    "bsconfig.json still present (migrate to rescript.json)"
                ),
            });
        }

        if matches!(metrics.jsx_version, Some(3)) {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("migration-jsx-{}", id_counter),
                description: "JSX v3 detected (migrate to JSX v4)".to_string(),
            });
        }

        if !metrics.uncurried {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("migration-uncurried-{}", id_counter),
                description: "Curried-by-default mode (migrate to uncurried)".to_string(),
            });
        }

        // Group deprecated patterns by category for summary constraints
        let mut category_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for p in &metrics.deprecated_patterns {
            *category_counts
                .entry(format!("{:?}", p.category))
                .or_insert(0) += p.count;
        }
        for (category, count) in &category_counts {
            id_counter += 1;
            constraints.push(PanllConstraint {
                id: format!("migration-pattern-{}", id_counter),
                description: format!("{} {} pattern occurrences to migrate", count, category),
            });
        }
    }

    constraints
}

/// Human-readable label for a weak point category
fn category_label(cat: WeakPointCategory) -> &'static str {
    match cat {
        WeakPointCategory::UncheckedAllocation => "unchecked-alloc",
        WeakPointCategory::UnboundedLoop => "unbounded-loop",
        WeakPointCategory::BlockingIO => "blocking-io",
        WeakPointCategory::UnsafeCode => "unsafe-code",
        WeakPointCategory::PanicPath => "panic-path",
        WeakPointCategory::RaceCondition => "race-condition",
        WeakPointCategory::DeadlockPotential => "deadlock",
        WeakPointCategory::ResourceLeak => "resource-leak",
        WeakPointCategory::CommandInjection => "cmd-injection",
        WeakPointCategory::UnsafeDeserialization => "unsafe-deser",
        WeakPointCategory::DynamicCodeExecution => "dynamic-exec",
        WeakPointCategory::UnsafeFFI => "unsafe-ffi",
        WeakPointCategory::AtomExhaustion => "atom-exhaustion",
        WeakPointCategory::InsecureProtocol => "insecure-proto",
        WeakPointCategory::ExcessivePermissions => "excess-perms",
        WeakPointCategory::PathTraversal => "path-traversal",
        WeakPointCategory::HardcodedSecret => "hardcoded-secret",
        WeakPointCategory::UncheckedError => "unchecked-error",
        WeakPointCategory::InfiniteRecursion => "infinite-recursion",
        WeakPointCategory::UnsafeTypeCoercion => "unsafe-coercion",
        WeakPointCategory::ProofDrift => "proof-drift",
    }
}

fn axis_label(axis: AttackAxis) -> String {
    match axis {
        AttackAxis::Cpu => "cpu",
        AttackAxis::Memory => "memory",
        AttackAxis::Disk => "disk",
        AttackAxis::Network => "network",
        AttackAxis::Concurrency => "concurrency",
        AttackAxis::Time => "time",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// System image export (fNIRS-style health map → PanLL imaging panel)
// ---------------------------------------------------------------------------

/// PanLL export for system health imaging — maps to the imaging sub-panel
/// of mass-panic in PanLL. Provides spatial risk data that PanLL renders as
/// a heatmap grid with risk-proximity edges.
#[derive(Debug, Serialize)]
struct PanllImageExport {
    format: String,
    generated_at: String,
    source: PanllSource,
    scan_surface: String,
    global_health: f64,
    global_risk: f64,
    node_count: usize,
    edge_count: usize,
    total_weak_points: usize,
    total_critical: usize,
    risk_distribution: PanllRiskDistribution,
    nodes: Vec<PanllImageNode>,
    edges: Vec<PanllImageEdge>,
}

#[derive(Debug, Serialize)]
struct PanllRiskDistribution {
    healthy: usize,
    low: usize,
    moderate: usize,
    high: usize,
    critical: usize,
}

#[derive(Debug, Serialize)]
struct PanllImageNode {
    id: String,
    name: String,
    health_score: f64,
    risk_intensity: f64,
    weak_point_density: f64,
    weak_point_count: usize,
    critical_count: usize,
    high_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    skipped: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    top_categories: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PanllImageEdge {
    from_node: String,
    to_node: String,
    edge_type: String,
    weight: f64,
}

fn export_image(image: &SystemImage) -> PanllImageExport {
    let nodes = image
        .nodes
        .iter()
        .map(|n| PanllImageNode {
            id: n.id.clone(),
            name: n.name.clone(),
            health_score: n.health_score,
            risk_intensity: n.risk_intensity,
            weak_point_density: n.weak_point_density,
            weak_point_count: n.weak_point_count,
            critical_count: n.critical_count,
            high_count: n.high_count,
            fingerprint: n.fingerprint.clone(),
            skipped: n.skipped,
            top_categories: n
                .categories
                .iter()
                .take(3)
                .map(|c| c.name.clone())
                .collect(),
        })
        .collect();

    let edges = image
        .edges
        .iter()
        .map(|e| PanllImageEdge {
            from_node: e.from_node.clone(),
            to_node: e.to_node.clone(),
            edge_type: format!("{:?}", e.edge_type),
            weight: e.weight,
        })
        .collect();

    PanllImageExport {
        format: "panll.system-image.v0".to_string(),
        generated_at: image.generated_at.clone(),
        source: PanllSource {
            tool: "panic-attack".to_string(),
            report_path: None,
        },
        scan_surface: image.scan_surface.clone(),
        global_health: image.global_health,
        global_risk: image.global_risk,
        node_count: image.node_count,
        edge_count: image.edge_count,
        total_weak_points: image.total_weak_points,
        total_critical: image.total_critical,
        risk_distribution: PanllRiskDistribution {
            healthy: image.risk_distribution.healthy,
            low: image.risk_distribution.low,
            moderate: image.risk_distribution.moderate,
            high: image.risk_distribution.high,
            critical: image.risk_distribution.critical,
        },
        nodes,
        edges,
    }
}

/// Write a PanLL system image export to JSON.
pub fn write_image_export(image: &SystemImage, output: &Path) -> Result<()> {
    let export = export_image(image);
    let json = serde_json::to_string_pretty(&export)?;
    fs::write(output, json)
        .with_context(|| format!("writing panll image export {}", output.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Temporal diff export (time-series navigation → PanLL temporal panel)
// ---------------------------------------------------------------------------

/// PanLL export for temporal navigation — maps to the temporal sub-panel
/// of mass-panic in PanLL. Provides diff data that PanLL renders as
/// trend arrows, health delta bars, and node-level change lists.
#[derive(Debug, Serialize)]
struct PanllTemporalExport {
    format: String,
    generated_at: String,
    source: PanllSource,
    from_label: String,
    to_label: String,
    from_timestamp: String,
    to_timestamp: String,
    health_delta: f64,
    risk_delta: f64,
    weak_point_delta: i64,
    critical_delta: i64,
    new_nodes: Vec<String>,
    removed_nodes: Vec<String>,
    improved_nodes: Vec<PanllNodeDelta>,
    degraded_nodes: Vec<PanllNodeDelta>,
    unchanged_count: usize,
    /// Overall trend: "improving", "degrading", or "stable"
    trend: String,
}

#[derive(Debug, Serialize)]
struct PanllNodeDelta {
    name: String,
    health_before: f64,
    health_after: f64,
    health_delta: f64,
    risk_before: f64,
    risk_after: f64,
    risk_delta: f64,
    weak_point_delta: i64,
}

fn export_temporal_diff(diff: &TemporalDiff) -> PanllTemporalExport {
    let trend = if diff.health_delta > 0.01 {
        "improving"
    } else if diff.health_delta < -0.01 {
        "degrading"
    } else {
        "stable"
    };

    let improved_nodes = diff
        .improved_nodes
        .iter()
        .map(|nd| PanllNodeDelta {
            name: nd.name.clone(),
            health_before: nd.health_before,
            health_after: nd.health_after,
            health_delta: nd.health_after - nd.health_before,
            risk_before: nd.risk_before,
            risk_after: nd.risk_after,
            risk_delta: nd.risk_after - nd.risk_before,
            weak_point_delta: nd.weak_points_after as i64 - nd.weak_points_before as i64,
        })
        .collect();

    let degraded_nodes = diff
        .degraded_nodes
        .iter()
        .map(|nd| PanllNodeDelta {
            name: nd.name.clone(),
            health_before: nd.health_before,
            health_after: nd.health_after,
            health_delta: nd.health_after - nd.health_before,
            risk_before: nd.risk_before,
            risk_after: nd.risk_after,
            risk_delta: nd.risk_after - nd.risk_before,
            weak_point_delta: nd.weak_points_after as i64 - nd.weak_points_before as i64,
        })
        .collect();

    PanllTemporalExport {
        format: "panll.temporal-diff.v0".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        source: PanllSource {
            tool: "panic-attack".to_string(),
            report_path: None,
        },
        from_label: diff.from_label.clone(),
        to_label: diff.to_label.clone(),
        from_timestamp: diff.from_timestamp.clone(),
        to_timestamp: diff.to_timestamp.clone(),
        health_delta: diff.health_delta,
        risk_delta: diff.risk_delta,
        weak_point_delta: diff.weak_point_delta,
        critical_delta: diff.critical_delta,
        new_nodes: diff.new_nodes.clone(),
        removed_nodes: diff.removed_nodes.clone(),
        improved_nodes,
        degraded_nodes,
        unchanged_count: diff.unchanged_count,
        trend: trend.to_string(),
    }
}

/// Write a PanLL temporal diff export to JSON.
pub fn write_temporal_export(diff: &TemporalDiff, output: &Path) -> Result<()> {
    let export = export_temporal_diff(diff);
    let json = serde_json::to_string_pretty(&export)?;
    fs::write(output, json)
        .with_context(|| format!("writing panll temporal export {}", output.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mass_panic::imaging::{
        CategoryCount, EdgeType, ImageEdge, ImageNode, NodeLevel, RiskDistribution,
    };
    use crate::mass_panic::temporal::{NodeDelta, Trend};
    use crate::types::*;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Helper: build a minimal AssaultReport with given weak points, attack
    /// results, taint rows, and critical issues.
    fn make_report(
        weak_points: Vec<WeakPoint>,
        attack_results: Vec<AttackResult>,
        taint_rows: Vec<TaintMatrixRow>,
        critical_issues: Vec<String>,
    ) -> AssaultReport {
        AssaultReport {
            assail_report: AssailReport {
                program_path: PathBuf::from("/tmp/test-target"),
                language: Language::Rust,
                frameworks: vec![],
                weak_points,
                statistics: ProgramStatistics::default(),
                file_statistics: vec![],
                dependency_graph: DependencyGraph { edges: vec![] },
                taint_matrix: TaintMatrix { rows: taint_rows },
                recommended_attacks: vec![],
                migration_metrics: None,
            suppressed_count: 0,
            },
            attack_results,
            total_crashes: 0,
            total_signatures: 0,
            overall_assessment: OverallAssessment {
                robustness_score: 80.0,
                critical_issues,
                recommendations: vec![],
            },
            timeline: None,
        }
    }

    // ------------------------------------------------------------------
    // 1. axis_label covers all AttackAxis variants
    // ------------------------------------------------------------------
    #[test]
    fn axis_label_returns_correct_strings() {
        assert_eq!(axis_label(AttackAxis::Cpu), "cpu");
        assert_eq!(axis_label(AttackAxis::Memory), "memory");
        assert_eq!(axis_label(AttackAxis::Disk), "disk");
        assert_eq!(axis_label(AttackAxis::Network), "network");
        assert_eq!(axis_label(AttackAxis::Concurrency), "concurrency");
        assert_eq!(axis_label(AttackAxis::Time), "time");
    }

    // ------------------------------------------------------------------
    // 2. category_label covers all WeakPointCategory variants
    // ------------------------------------------------------------------
    #[test]
    fn category_label_returns_correct_strings() {
        assert_eq!(category_label(WeakPointCategory::UnsafeCode), "unsafe-code");
        assert_eq!(category_label(WeakPointCategory::PanicPath), "panic-path");
        assert_eq!(
            category_label(WeakPointCategory::CommandInjection),
            "cmd-injection"
        );
        assert_eq!(
            category_label(WeakPointCategory::UnsafeDeserialization),
            "unsafe-deser"
        );
        assert_eq!(
            category_label(WeakPointCategory::AtomExhaustion),
            "atom-exhaustion"
        );
        assert_eq!(
            category_label(WeakPointCategory::HardcodedSecret),
            "hardcoded-secret"
        );
        assert_eq!(
            category_label(WeakPointCategory::UnsafeTypeCoercion),
            "unsafe-coercion"
        );
    }

    // ------------------------------------------------------------------
    // 3. export_report builds correct format, summary, and event chain
    // ------------------------------------------------------------------
    #[test]
    fn export_report_populates_format_and_summary() {
        let report = make_report(
            vec![
                WeakPoint {
                    category: WeakPointCategory::PanicPath,
                    location: Some("src/main.rs:10".to_string()),
                    file: None,
                    line: None,
                    severity: Severity::Critical,
                    description: "unwrap on None".to_string(),
                    recommended_attack: vec![],
                    suppressed: false,
                },
                WeakPoint {
                    category: WeakPointCategory::UnsafeCode,
                    location: Some("src/lib.rs:20".to_string()),
                    file: None,
                    line: None,
                    severity: Severity::High,
                    description: "unsafe block".to_string(),
                    recommended_attack: vec![],
                    suppressed: false,
                },
            ],
            vec![],
            vec![],
            vec![],
        );

        let export = export_report(&report, None);

        assert_eq!(export.format, "panll.event-chain.v0");
        assert_eq!(export.source.tool, "panic-attack");
        assert!(export.source.report_path.is_none());
        assert_eq!(export.summary.weak_points, 2);
        assert_eq!(export.summary.critical_weak_points, 1);
        assert_eq!(export.summary.robustness_score, 80.0);
        assert_eq!(
            export.summary.program,
            "/tmp/test-target"
        );
    }

    // ------------------------------------------------------------------
    // 4. extract_constraints covers critical WPs, taint rows, failed
    //    attacks, and critical issues
    // ------------------------------------------------------------------
    #[test]
    fn extract_constraints_combines_all_sources() {
        let report = make_report(
            // One critical WP -> generates constraint
            vec![WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some("src/run.rs:42".to_string()),
                file: None,
                line: None,
                severity: Severity::Critical,
                description: "shell exec from user input".to_string(),
                recommended_attack: vec![AttackAxis::Cpu],
                    suppressed: false,
            }],
            // One failed attack -> generates constraint
            vec![AttackResult {
                program: PathBuf::from("/tmp/target"),
                axis: AttackAxis::Memory,
                success: false,
                skipped: false,
                skip_reason: None,
                exit_code: Some(139),
                duration: Duration::from_millis(100),
                peak_memory: 8192,
                crashes: vec![CrashReport {
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    signal: Some("SIGSEGV".to_string()),
                    backtrace: None,
                    stderr: "segfault".to_string(),
                    stdout: String::new(),
                }],
                signatures_detected: vec![],
            }],
            // One high-severity taint row -> generates constraint
            vec![TaintMatrixRow {
                source_category: WeakPointCategory::UnsafeDeserialization,
                sink_axis: AttackAxis::Network,
                severity_value: 8.5,
                files: vec!["src/api.rs".to_string()],
                frameworks: vec![],
                relation: "deserialization to network sink".to_string(),
            }],
            // One critical issue string -> generates constraint
            vec!["memory safety violation detected".to_string()],
        );

        let constraints = extract_constraints(&report);

        // Expect 4 constraints: 1 critical WP + 1 taint + 1 failed attack + 1 critical issue
        assert_eq!(constraints.len(), 4);

        // Verify constraint IDs and descriptions
        assert!(constraints[0].id.starts_with("wp-crit-"));
        assert!(constraints[0].description.contains("cmd-injection"));
        assert!(constraints[0].description.contains("src/run.rs:42"));

        assert!(constraints[1].id.starts_with("taint-"));
        assert!(constraints[1].description.contains("Taint flow"));
        assert!(constraints[1].description.contains("8.5"));

        assert!(constraints[2].id.starts_with("attack-fail-"));
        assert!(constraints[2].description.contains("memory"));
        assert!(constraints[2].description.contains("1 crashes"));

        assert!(constraints[3].id.starts_with("critical-"));
        assert_eq!(
            constraints[3].description,
            "memory safety violation detected"
        );
    }

    // ------------------------------------------------------------------
    // 5. export_report builds event chain from attack results when no
    //    timeline is present
    // ------------------------------------------------------------------
    #[test]
    fn export_report_builds_event_chain_from_attack_results() {
        let report = make_report(
            vec![],
            vec![
                AttackResult {
                    program: PathBuf::from("/tmp/t"),
                    axis: AttackAxis::Disk,
                    success: true,
                    skipped: false,
                    skip_reason: None,
                    exit_code: Some(0),
                    duration: Duration::from_millis(300),
                    peak_memory: 2048,
                    crashes: vec![],
                    signatures_detected: vec![],
                },
                AttackResult {
                    program: PathBuf::from("/tmp/t"),
                    axis: AttackAxis::Network,
                    success: false,
                    skipped: true,
                    skip_reason: Some("no network flag".to_string()),
                    exit_code: None,
                    duration: Duration::from_millis(0),
                    peak_memory: 0,
                    crashes: vec![],
                    signatures_detected: vec![],
                },
            ],
            vec![],
            vec![],
        );

        let export = export_report(&report, None);

        assert_eq!(export.event_chain.len(), 2);

        // First event: passed disk attack
        assert_eq!(export.event_chain[0].axis, "disk");
        assert_eq!(export.event_chain[0].status, "passed");
        assert_eq!(export.event_chain[0].duration_ms, 300);
        assert_eq!(export.event_chain[0].peak_memory, Some(2048));
        assert!(export.event_chain[0].notes.is_none());

        // Second event: skipped network attack
        assert_eq!(export.event_chain[1].axis, "network");
        assert_eq!(export.event_chain[1].status, "skipped");
        assert_eq!(
            export.event_chain[1].notes.as_deref(),
            Some("no network flag")
        );
    }

    // ------------------------------------------------------------------
    // 6. export_report builds event chain from timeline when present
    // ------------------------------------------------------------------
    #[test]
    fn export_report_uses_timeline_events_when_available() {
        let mut report = make_report(vec![], vec![], vec![], vec![]);
        report.timeline = Some(TimelineReport {
            duration: Duration::from_secs(5),
            events: vec![TimelineEventReport {
                id: "ev-cpu-1".to_string(),
                axis: AttackAxis::Cpu,
                start_offset: Duration::from_millis(100),
                duration: Duration::from_millis(900),
                intensity: IntensityLevel::Heavy,
                args: vec![],
                peak_memory: Some(4096),
                ran: true,
            }],
        });

        let export = export_report(&report, None);

        // Timeline should be present
        assert!(export.timeline.is_some());
        let tl = export.timeline.unwrap();
        assert_eq!(tl.duration_ms, 5000);
        assert_eq!(tl.events, 1);

        // Event chain should come from timeline, not attack_results
        assert_eq!(export.event_chain.len(), 1);
        assert_eq!(export.event_chain[0].id, "ev-cpu-1");
        assert_eq!(export.event_chain[0].axis, "cpu");
        assert_eq!(export.event_chain[0].status, "ran");
        assert_eq!(export.event_chain[0].start_ms, Some(100));
        assert_eq!(export.event_chain[0].duration_ms, 900);
    }

    // ------------------------------------------------------------------
    // 7. write_export produces valid JSON on disk
    // ------------------------------------------------------------------
    #[test]
    fn write_export_creates_valid_json_file() {
        let report = make_report(vec![], vec![], vec![], vec![]);
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("panll.json");

        write_export(&report, None, &output).unwrap();

        let content = fs::read_to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["format"], "panll.event-chain.v0");
        assert!(parsed["generated_at"].as_str().is_some());
    }

    // ------------------------------------------------------------------
    // 8. export_image maps SystemImage nodes and edges correctly
    // ------------------------------------------------------------------
    #[test]
    fn export_image_maps_nodes_and_edges() {
        let image = SystemImage {
            format: "panic-attack.system-image.v1".to_string(),
            generated_at: "2026-04-01T00:00:00Z".to_string(),
            scan_surface: "/repos".to_string(),
            node_count: 2,
            edge_count: 1,
            global_health: 0.75,
            global_risk: 0.25,
            total_weak_points: 10,
            total_critical: 2,
            total_lines: 5000,
            total_files: 30,
            repos_scanned: 2,
            nodes: vec![
                ImageNode {
                    id: "repo:alpha".to_string(),
                    path: "/repos/alpha".to_string(),
                    name: "alpha".to_string(),
                    level: NodeLevel::Repository,
                    health_score: 0.8,
                    risk_intensity: 0.2,
                    weak_point_density: 1.5,
                    weak_point_count: 3,
                    critical_count: 1,
                    high_count: 1,
                    total_files: 15,
                    total_lines: 3000,
                    fingerprint: Some("abc".to_string()),
                    skipped: false,
                    error: None,
                    categories: vec![
                        CategoryCount {
                            name: "PanicPath".to_string(),
                            count: 5,
                        },
                        CategoryCount {
                            name: "UnsafeCode".to_string(),
                            count: 3,
                        },
                        CategoryCount {
                            name: "ResourceLeak".to_string(),
                            count: 1,
                        },
                        CategoryCount {
                            name: "Rare".to_string(),
                            count: 1,
                        },
                    ],
                },
                ImageNode {
                    id: "repo:beta".to_string(),
                    path: "/repos/beta".to_string(),
                    name: "beta".to_string(),
                    level: NodeLevel::Repository,
                    health_score: 0.6,
                    risk_intensity: 0.4,
                    weak_point_density: 3.0,
                    weak_point_count: 7,
                    critical_count: 1,
                    high_count: 2,
                    total_files: 15,
                    total_lines: 2000,
                    fingerprint: None,
                    skipped: false,
                    error: None,
                    categories: vec![],
                },
            ],
            edges: vec![ImageEdge {
                from_node: "repo:alpha".to_string(),
                to_node: "repo:beta".to_string(),
                edge_type: EdgeType::RiskProximity,
                weight: 0.9,
            }],
            risk_distribution: RiskDistribution {
                healthy: 1,
                low: 1,
                moderate: 0,
                high: 0,
                critical: 0,
            },
        };

        let export = export_image(&image);

        assert_eq!(export.format, "panll.system-image.v0");
        assert_eq!(export.scan_surface, "/repos");
        assert_eq!(export.global_health, 0.75);
        assert_eq!(export.global_risk, 0.25);
        assert_eq!(export.node_count, 2);
        assert_eq!(export.edge_count, 1);
        assert_eq!(export.total_weak_points, 10);
        assert_eq!(export.total_critical, 2);

        // Nodes mapped correctly
        assert_eq!(export.nodes.len(), 2);
        assert_eq!(export.nodes[0].id, "repo:alpha");
        assert_eq!(export.nodes[0].name, "alpha");
        assert_eq!(export.nodes[0].fingerprint, Some("abc".to_string()));
        // top_categories limited to 3
        assert_eq!(export.nodes[0].top_categories.len(), 3);
        assert_eq!(export.nodes[0].top_categories[0], "PanicPath");
        // beta has no categories
        assert!(export.nodes[1].top_categories.is_empty());

        // Edge mapped correctly
        assert_eq!(export.edges.len(), 1);
        assert_eq!(export.edges[0].from_node, "repo:alpha");
        assert_eq!(export.edges[0].to_node, "repo:beta");
        assert_eq!(export.edges[0].weight, 0.9);
    }

    // ------------------------------------------------------------------
    // 9. export_temporal_diff sets trend correctly
    // ------------------------------------------------------------------
    #[test]
    fn export_temporal_diff_sets_trend_based_on_health_delta() {
        // Improving case: health_delta > 0.01
        let diff_improving = TemporalDiff {
            format: "panic-attack.temporal-diff.v1".to_string(),
            from_timestamp: "2026-01-01T00:00:00Z".to_string(),
            to_timestamp: "2026-02-01T00:00:00Z".to_string(),
            from_label: "jan".to_string(),
            to_label: "feb".to_string(),
            health_delta: 0.15,
            risk_delta: -0.15,
            weak_point_delta: -5,
            critical_delta: -1,
            new_nodes: vec![],
            removed_nodes: vec![],
            improved_nodes: vec![NodeDelta {
                node_id: "repo:a".to_string(),
                name: "a".to_string(),
                health_before: 0.5,
                health_after: 0.65,
                risk_before: 0.5,
                risk_after: 0.35,
                weak_points_before: 10,
                weak_points_after: 5,
            }],
            degraded_nodes: vec![],
            unchanged_count: 0,
            trend: Trend::Improving,
        };

        let export = export_temporal_diff(&diff_improving);
        assert_eq!(export.format, "panll.temporal-diff.v0");
        assert_eq!(export.trend, "improving");
        assert_eq!(export.from_label, "jan");
        assert_eq!(export.to_label, "feb");
        assert_eq!(export.health_delta, 0.15);
        assert_eq!(export.weak_point_delta, -5);

        // Improved nodes mapped with computed deltas
        assert_eq!(export.improved_nodes.len(), 1);
        assert_eq!(export.improved_nodes[0].name, "a");
        let h_delta = export.improved_nodes[0].health_delta;
        assert!((h_delta - 0.15).abs() < 0.001);

        // Degrading case: health_delta < -0.01
        let diff_degrading = TemporalDiff {
            format: "panic-attack.temporal-diff.v1".to_string(),
            from_timestamp: "2026-01-01T00:00:00Z".to_string(),
            to_timestamp: "2026-02-01T00:00:00Z".to_string(),
            from_label: "before".to_string(),
            to_label: "after".to_string(),
            health_delta: -0.20,
            risk_delta: 0.20,
            weak_point_delta: 8,
            critical_delta: 3,
            new_nodes: vec!["repo:new".to_string()],
            removed_nodes: vec!["repo:old".to_string()],
            improved_nodes: vec![],
            degraded_nodes: vec![],
            unchanged_count: 5,
            trend: Trend::Degrading,
        };

        let export2 = export_temporal_diff(&diff_degrading);
        assert_eq!(export2.trend, "degrading");
        assert_eq!(export2.new_nodes, vec!["repo:new"]);
        assert_eq!(export2.removed_nodes, vec!["repo:old"]);
        assert_eq!(export2.unchanged_count, 5);

        // Stable case: health_delta near zero
        let diff_stable = TemporalDiff {
            format: "panic-attack.temporal-diff.v1".to_string(),
            from_timestamp: "2026-01-01T00:00:00Z".to_string(),
            to_timestamp: "2026-02-01T00:00:00Z".to_string(),
            from_label: "v1".to_string(),
            to_label: "v2".to_string(),
            health_delta: 0.005,
            risk_delta: -0.005,
            weak_point_delta: 0,
            critical_delta: 0,
            new_nodes: vec![],
            removed_nodes: vec![],
            improved_nodes: vec![],
            degraded_nodes: vec![],
            unchanged_count: 10,
            trend: Trend::Stable,
        };

        let export3 = export_temporal_diff(&diff_stable);
        assert_eq!(export3.trend, "stable");
    }

    // ------------------------------------------------------------------
    // 10. write_image_export and write_temporal_export round-trip to disk
    // ------------------------------------------------------------------
    #[test]
    fn write_image_export_creates_valid_json() {
        let image = SystemImage {
            format: "panic-attack.system-image.v1".to_string(),
            generated_at: "2026-04-01T00:00:00Z".to_string(),
            scan_surface: "/repos".to_string(),
            node_count: 0,
            edge_count: 0,
            global_health: 1.0,
            global_risk: 0.0,
            total_weak_points: 0,
            total_critical: 0,
            total_lines: 0,
            total_files: 0,
            repos_scanned: 0,
            nodes: vec![],
            edges: vec![],
            risk_distribution: RiskDistribution::default(),
        };
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("image.json");

        write_image_export(&image, &output).unwrap();

        let content = fs::read_to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["format"], "panll.system-image.v0");
        assert_eq!(parsed["global_health"], 1.0);
        assert_eq!(parsed["node_count"], 0);
    }

    #[test]
    fn write_temporal_export_creates_valid_json() {
        let diff = TemporalDiff {
            format: "panic-attack.temporal-diff.v1".to_string(),
            from_timestamp: "2026-01-01T00:00:00Z".to_string(),
            to_timestamp: "2026-03-01T00:00:00Z".to_string(),
            from_label: "q1".to_string(),
            to_label: "q2".to_string(),
            health_delta: 0.1,
            risk_delta: -0.1,
            weak_point_delta: -3,
            critical_delta: -1,
            new_nodes: vec![],
            removed_nodes: vec![],
            improved_nodes: vec![],
            degraded_nodes: vec![],
            unchanged_count: 4,
            trend: Trend::Improving,
        };
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("temporal.json");

        write_temporal_export(&diff, &output).unwrap();

        let content = fs::read_to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["format"], "panll.temporal-diff.v0");
        assert_eq!(parsed["from_label"], "q1");
        assert_eq!(parsed["to_label"], "q2");
        assert_eq!(parsed["trend"], "improving");
    }

    // ------------------------------------------------------------------
    // 11. extract_constraints ignores low-severity taint rows
    // ------------------------------------------------------------------
    #[test]
    fn extract_constraints_skips_low_severity_taint() {
        let report = make_report(
            vec![],
            vec![],
            vec![TaintMatrixRow {
                source_category: WeakPointCategory::PathTraversal,
                sink_axis: AttackAxis::Disk,
                severity_value: 3.0, // below 7.0 threshold
                files: vec!["src/io.rs".to_string()],
                frameworks: vec![],
                relation: "low risk path".to_string(),
            }],
            vec![],
        );

        let constraints = extract_constraints(&report);
        assert!(
            constraints.is_empty(),
            "taint rows with severity < 7.0 should not generate constraints"
        );
    }
}
