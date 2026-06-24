// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Diff utilities for assault reports.

use crate::types::*;
use anyhow::{Context, Result};
use serde_json;
use serde_yaml;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Upper bound on assault report JSON/YAML reads. Reports are emitted by
/// panic-attack itself; 64 MiB is two orders of magnitude beyond any
/// realistic report size and protects against a tampered or malformed
/// input loaded into memory wholesale.
const REPORT_FILE_READ_LIMIT: u64 = 64 * 1024 * 1024;

pub fn load_report(path: &Path) -> Result<AssaultReport> {
    let content = {
        let mut buf = String::new();
        File::open(path)
            .with_context(|| format!("opening report {}", path.display()))?
            .take(REPORT_FILE_READ_LIMIT)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading report {}", path.display()))?;
        buf
    };
    // Diff loader accepts JSON/YAML to match report export formats.
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
            .with_context(|| format!("parsing yaml report {}", path.display())),
        _ => serde_json::from_str(&content)
            .with_context(|| format!("parsing json report {}", path.display())),
    }
}

pub fn format_diff(
    base: &AssaultReport,
    compare: &AssaultReport,
    base_label: &str,
    compare_label: &str,
) -> String {
    // Diff output is human-first text, optimized for terminal/code-review workflows.
    let mut lines = Vec::new();
    lines.push("=== PANIC-ATTACK REPORT DIFF ===".to_string());
    lines.push(format!("Base: {}", base_label));
    lines.push(format!("Compare: {}", compare_label));
    lines.push(String::new());

    let score_delta =
        compare.overall_assessment.robustness_score - base.overall_assessment.robustness_score;
    lines.push(format!(
        "Robustness score: {:.1} -> {:.1} ({:+.1})",
        base.overall_assessment.robustness_score,
        compare.overall_assessment.robustness_score,
        score_delta
    ));

    let crash_delta = compare.total_crashes as i64 - base.total_crashes as i64;
    lines.push(format!(
        "Total crashes: {} -> {} ({})",
        base.total_crashes,
        compare.total_crashes,
        fmt_delta_i64(crash_delta)
    ));

    let sig_delta = compare.total_signatures as i64 - base.total_signatures as i64;
    lines.push(format!(
        "Total signatures: {} -> {} ({})",
        base.total_signatures,
        compare.total_signatures,
        fmt_delta_i64(sig_delta)
    ));

    let weak_delta = compare.assail_report.weak_points.len() as i64
        - base.assail_report.weak_points.len() as i64;
    lines.push(format!(
        "Weak points: {} -> {} ({})",
        base.assail_report.weak_points.len(),
        compare.assail_report.weak_points.len(),
        fmt_delta_i64(weak_delta)
    ));

    lines.push(String::new());
    lines.extend(format_attack_summary(base, compare));
    lines.push(String::new());
    lines.extend(format_assail_summary(base, compare));

    lines.join("\n")
}

fn format_attack_summary(base: &AssaultReport, compare: &AssaultReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("Attack outcomes:".to_string());
    let (base_pass, base_fail, base_skip) = count_attack_status(&base.attack_results);
    let (cmp_pass, cmp_fail, cmp_skip) = count_attack_status(&compare.attack_results);

    lines.push(format!(
        "  Passed: {} -> {} ({})",
        base_pass,
        cmp_pass,
        fmt_delta_i64(cmp_pass as i64 - base_pass as i64)
    ));
    lines.push(format!(
        "  Failed: {} -> {} ({})",
        base_fail,
        cmp_fail,
        fmt_delta_i64(cmp_fail as i64 - base_fail as i64)
    ));
    lines.push(format!(
        "  Skipped: {} -> {} ({})",
        base_skip,
        cmp_skip,
        fmt_delta_i64(cmp_skip as i64 - base_skip as i64)
    ));

    // Per-axis deltas compress many individual runs into a quick triage surface.
    let base_axes = axis_status_map(&base.attack_results);
    let compare_axes = axis_status_map(&compare.attack_results);
    if !base_axes.is_empty() || !compare_axes.is_empty() {
        lines.push("  Per-axis status:".to_string());
        for axis in AttackAxis::all() {
            let base_status = base_axes
                .get(&axis)
                .cloned()
                .unwrap_or_else(|| "-".to_string());
            let compare_status = compare_axes
                .get(&axis)
                .cloned()
                .unwrap_or_else(|| "-".to_string());
            if base_status != "-" || compare_status != "-" {
                lines.push(format!(
                    "    {:?}: {} -> {}",
                    axis, base_status, compare_status
                ));
            }
        }
    }

    lines
}

fn format_assail_summary(base: &AssaultReport, compare: &AssaultReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("Assail summary:".to_string());

    let base_fw: HashSet<_> = base.assail_report.frameworks.iter().copied().collect();
    let cmp_fw: HashSet<_> = compare.assail_report.frameworks.iter().copied().collect();
    let added_fw: Vec<_> = cmp_fw.difference(&base_fw).collect();
    let removed_fw: Vec<_> = base_fw.difference(&cmp_fw).collect();

    lines.push(format!(
        "  Frameworks: +{} -{}",
        fmt_list(&added_fw),
        fmt_list(&removed_fw)
    ));

    let base_rec: HashSet<_> = base
        .assail_report
        .recommended_attacks
        .iter()
        .copied()
        .collect();
    let cmp_rec: HashSet<_> = compare
        .assail_report
        .recommended_attacks
        .iter()
        .copied()
        .collect();
    let added_rec: Vec<_> = cmp_rec.difference(&base_rec).collect();
    let removed_rec: Vec<_> = base_rec.difference(&cmp_rec).collect();
    lines.push(format!(
        "  Recommended attacks: +{} -{}",
        fmt_list(&added_rec),
        fmt_list(&removed_rec)
    ));

    let base_deps = base.assail_report.dependency_graph.edges.len() as i64;
    let cmp_deps = compare.assail_report.dependency_graph.edges.len() as i64;
    lines.push(format!(
        "  Dependency edges: {} -> {} ({})",
        base_deps,
        cmp_deps,
        fmt_delta_i64(cmp_deps - base_deps)
    ));

    let base_matrix = base.assail_report.taint_matrix.rows.len() as i64;
    let cmp_matrix = compare.assail_report.taint_matrix.rows.len() as i64;
    lines.push(format!(
        "  Taint matrix rows: {} -> {} ({})",
        base_matrix,
        cmp_matrix,
        fmt_delta_i64(cmp_matrix - base_matrix)
    ));

    let base_severity = count_severity(&base.assail_report.weak_points);
    let cmp_severity = count_severity(&compare.assail_report.weak_points);
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let base_count = *base_severity.get(&severity).unwrap_or(&0);
        let cmp_count = *cmp_severity.get(&severity).unwrap_or(&0);
        if base_count > 0 || cmp_count > 0 {
            lines.push(format!(
                "  {:?}: {} -> {} ({})",
                severity,
                base_count,
                cmp_count,
                fmt_delta_i64(cmp_count as i64 - base_count as i64)
            ));
        }
    }

    lines
}

fn fmt_delta_i64(delta: i64) -> String {
    if delta > 0 {
        format!("+{}", delta)
    } else {
        delta.to_string()
    }
}

fn count_attack_status(results: &[AttackResult]) -> (usize, usize, usize) {
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

fn axis_status_map(results: &[AttackResult]) -> HashMap<AttackAxis, String> {
    let mut map: HashMap<AttackAxis, Vec<&AttackResult>> = HashMap::new();
    for result in results {
        map.entry(result.axis).or_default().push(result);
    }

    map.into_iter()
        .map(|(axis, entries)| (axis, summarize_axis(entries)))
        .collect()
}

fn summarize_axis(entries: Vec<&AttackResult>) -> String {
    // Any non-skipped failure dominates axis status for conservative reporting.
    if entries.iter().any(|r| !r.skipped && !r.success) {
        "failed".to_string()
    } else if entries.iter().any(|r| r.skipped) {
        "skipped".to_string()
    } else if entries.iter().any(|r| r.success) {
        "passed".to_string()
    } else {
        "-".to_string()
    }
}

fn fmt_list<T: std::fmt::Debug>(items: &[&T]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items
            .iter()
            .map(|item| format!("{:?}", item))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn count_severity(points: &[WeakPoint]) -> BTreeMap<Severity, usize> {
    let mut map = BTreeMap::new();
    for point in points {
        *map.entry(point.severity).or_insert(0) += 1;
    }
    map
}
