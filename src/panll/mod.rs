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
