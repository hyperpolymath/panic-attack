// SPDX-License-Identifier: MPL-2.0

//! Migration diff report formatter
//!
//! Produces human-readable markdown comparing two ReScript migration
//! snapshots (before/after). Tables show health score changes,
//! deprecated API removals, build time deltas, and bundle size deltas.

use crate::types::{DeprecatedCategory, MigrationDiff, MigrationSnapshot, ReScriptConfigFormat};

/// Upper bound on migration-snapshot reads. Snapshots are small JSON
/// summaries produced by panic-attack; 4 MiB is an order of magnitude
/// beyond any realistic snapshot and bounds a tampered or malformed
/// input wholesale.
const SNAPSHOT_FILE_READ_LIMIT: u64 = 4 * 1024 * 1024;

/// Load a migration snapshot from a JSON file
pub fn load_snapshot(path: &std::path::Path) -> anyhow::Result<MigrationSnapshot> {
    use std::io::Read;
    let content = {
        let mut buf = String::new();
        std::fs::File::open(path)
            .with_context(|| format!("opening migration snapshot {}", path.display()))?
            .take(SNAPSHOT_FILE_READ_LIMIT)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading migration snapshot {}", path.display()))?;
        buf
    };
    let snapshot: MigrationSnapshot = serde_json::from_str(&content)
        .with_context(|| format!("parsing migration snapshot {}", path.display()))?;
    Ok(snapshot)
}

/// Compute a diff between two migration snapshots
pub fn compute_diff(before: &MigrationSnapshot, after: &MigrationSnapshot) -> MigrationDiff {
    let bm = &before.migration_metrics;
    let am = &after.migration_metrics;

    // Find patterns removed (in before but not in after)
    let patterns_removed: Vec<_> = bm
        .deprecated_patterns
        .iter()
        .filter(|bp| {
            !am.deprecated_patterns
                .iter()
                .any(|ap| ap.pattern == bp.pattern && ap.file_path == bp.file_path)
        })
        .cloned()
        .collect();

    // Find patterns added (in after but not in before — regressions)
    let patterns_added: Vec<_> = am
        .deprecated_patterns
        .iter()
        .filter(|ap| {
            !bm.deprecated_patterns
                .iter()
                .any(|bp| bp.pattern == ap.pattern && bp.file_path == ap.file_path)
        })
        .cloned()
        .collect();

    let build_time_delta_ms = match (bm.build_time_ms, am.build_time_ms) {
        (Some(b), Some(a)) => Some(a as i64 - b as i64),
        _ => None,
    };

    let bundle_size_delta_bytes = match (bm.bundle_size_bytes, am.bundle_size_bytes) {
        (Some(b), Some(a)) => Some(a as i64 - b as i64),
        _ => None,
    };

    MigrationDiff {
        before_label: before.label.clone(),
        after_label: after.label.clone(),
        health_delta: am.health_score - bm.health_score,
        deprecated_delta: am.deprecated_api_count as i64 - bm.deprecated_api_count as i64,
        modern_delta: am.modern_api_count as i64 - bm.modern_api_count as i64,
        build_time_delta_ms,
        bundle_size_delta_bytes,
        patterns_removed,
        patterns_added,
        version_before: bm.version_bracket,
        version_after: am.version_bracket,
        config_before: bm.config_format,
        config_after: am.config_format,
    }
}

/// Format a migration diff as a markdown report
pub fn format_diff_markdown(diff: &MigrationDiff) -> String {
    let mut out = String::new();

    out.push_str("# ReScript Migration Diff Report\n\n");
    out.push_str(&format!(
        "**Before:** {} → **After:** {}\n\n",
        diff.before_label, diff.after_label
    ));

    // Health score
    out.push_str("## Health Score\n\n");
    let health_arrow = if diff.health_delta > 0.0 {
        "improved"
    } else if diff.health_delta < 0.0 {
        "regressed"
    } else {
        "unchanged"
    };
    out.push_str(&format!(
        "Health score {}: **{:+.2}**\n\n",
        health_arrow, diff.health_delta
    ));

    // Summary table
    out.push_str("## Metrics\n\n");
    out.push_str("| Metric | Delta | Direction |\n");
    out.push_str("|--------|-------|-----------|\n");
    out.push_str(&format!(
        "| Deprecated APIs | {} | {} |\n",
        fmt_delta(diff.deprecated_delta),
        direction_emoji(diff.deprecated_delta, true)
    ));
    out.push_str(&format!(
        "| Modern APIs | {} | {} |\n",
        fmt_delta(diff.modern_delta),
        direction_emoji(diff.modern_delta, false)
    ));
    if let Some(bt) = diff.build_time_delta_ms {
        out.push_str(&format!(
            "| Build time (ms) | {} | {} |\n",
            fmt_delta(bt),
            direction_emoji(bt, true)
        ));
    }
    if let Some(bs) = diff.bundle_size_delta_bytes {
        out.push_str(&format!(
            "| Bundle size (bytes) | {} | {} |\n",
            fmt_delta(bs),
            direction_emoji(bs, true)
        ));
    }
    out.push('\n');

    // Version bracket change
    if diff.version_before != diff.version_after {
        out.push_str("## Version Bracket\n\n");
        out.push_str(&format!(
            "{} -> {}\n\n",
            diff.version_before, diff.version_after
        ));
    }

    // Config format change
    if diff.config_before != diff.config_after {
        out.push_str("## Config Format\n\n");
        out.push_str(&format!(
            "{} -> {}\n\n",
            config_label(diff.config_before),
            config_label(diff.config_after)
        ));
    }

    // Patterns removed (improvements)
    if !diff.patterns_removed.is_empty() {
        out.push_str("## Deprecated Patterns Removed\n\n");
        out.push_str("| Pattern | Replacement | File | Count | Category |\n");
        out.push_str("|---------|-------------|------|-------|----------|\n");
        for p in &diff.patterns_removed {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} |\n",
                p.pattern,
                p.replacement,
                p.file_path,
                p.count,
                category_label(p.category)
            ));
        }
        out.push('\n');
    }

    // Patterns added (regressions)
    if !diff.patterns_added.is_empty() {
        out.push_str("## Regressions (New Deprecated Patterns)\n\n");
        out.push_str("| Pattern | File | Count | Category |\n");
        out.push_str("|---------|------|-------|----------|\n");
        for p in &diff.patterns_added {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                p.pattern,
                p.file_path,
                p.count,
                category_label(p.category)
            ));
        }
        out.push('\n');
    }

    out
}

/// Format a single migration snapshot as a summary markdown section
#[allow(dead_code)]
pub fn format_snapshot_summary(snapshot: &MigrationSnapshot) -> String {
    let m = &snapshot.migration_metrics;
    let mut out = String::new();

    out.push_str(&format!("## Migration Snapshot: {}\n\n", snapshot.label));
    out.push_str(&format!("**Target:** {}\n", snapshot.target_path));
    out.push_str(&format!("**Timestamp:** {}\n", snapshot.timestamp));
    out.push_str(&format!("**Version bracket:** {}\n", m.version_bracket));
    out.push_str(&format!(
        "**Config format:** {}\n",
        config_label(m.config_format)
    ));
    out.push_str(&format!("**Health score:** {:.2}\n", m.health_score));
    out.push_str(&format!(
        "**API migration ratio:** {:.1}%\n",
        m.api_migration_ratio * 100.0
    ));
    out.push_str(&format!(
        "**Files:** {} ({} lines)\n",
        m.file_count, m.rescript_lines
    ));
    out.push_str(&format!(
        "**Deprecated APIs:** {} | **Modern APIs:** {}\n",
        m.deprecated_api_count, m.modern_api_count
    ));
    if let Some(jsx) = m.jsx_version {
        out.push_str(&format!("**JSX version:** {}\n", jsx));
    }
    out.push_str(&format!(
        "**Uncurried:** {}\n",
        if m.uncurried { "yes" } else { "no" }
    ));
    if let Some(ref mf) = m.module_format {
        out.push_str(&format!("**Module format:** {}\n", mf));
    }
    if let Some(bt) = m.build_time_ms {
        out.push_str(&format!("**Build time:** {}ms\n", bt));
    }
    if let Some(bs) = m.bundle_size_bytes {
        out.push_str(&format!("**Bundle size:** {} bytes\n", bs));
    }
    out.push('\n');

    if !m.deprecated_patterns.is_empty() {
        out.push_str("### Deprecated Patterns\n\n");
        out.push_str("| Pattern | Replacement | File | Count |\n");
        out.push_str("|---------|-------------|------|-------|\n");
        for p in &m.deprecated_patterns {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                p.pattern, p.replacement, p.file_path, p.count
            ));
        }
        out.push('\n');
    }

    out
}

fn fmt_delta(value: i64) -> String {
    if value > 0 {
        format!("+{}", value)
    } else {
        format!("{}", value)
    }
}

/// Direction indicator: for "lower is better" metrics (deprecated, build time),
/// negative = good. For "higher is better" (modern APIs), positive = good.
fn direction_emoji(value: i64, lower_is_better: bool) -> &'static str {
    if value == 0 {
        return "-";
    }
    if lower_is_better {
        if value < 0 {
            "IMPROVED"
        } else {
            "REGRESSED"
        }
    } else if value > 0 {
        "IMPROVED"
    } else {
        "REGRESSED"
    }
}

fn config_label(config: ReScriptConfigFormat) -> &'static str {
    match config {
        ReScriptConfigFormat::BsConfig => "bsconfig.json",
        ReScriptConfigFormat::RescriptJson => "rescript.json",
        ReScriptConfigFormat::Both => "both (bsconfig.json + rescript.json)",
        ReScriptConfigFormat::None => "none",
    }
}

fn category_label(cat: DeprecatedCategory) -> &'static str {
    match cat {
        DeprecatedCategory::JsApi => "Js.*",
        DeprecatedCategory::BeltApi => "Belt.*",
        DeprecatedCategory::BsConfig => "bsconfig",
        DeprecatedCategory::CurriedDefault => "curried-default",
        DeprecatedCategory::OldJsx => "old-jsx",
        DeprecatedCategory::OldJson => "old-json",
        DeprecatedCategory::OldDict => "old-dict",
        DeprecatedCategory::OldNullable => "old-nullable",
        DeprecatedCategory::OldConsole => "old-console",
        DeprecatedCategory::OldPromise => "old-promise",
        DeprecatedCategory::OldNumeric => "old-numeric",
        DeprecatedCategory::OldRegExp => "old-regexp",
        DeprecatedCategory::OldDate => "old-date",
        DeprecatedCategory::OldReactStyle => "old-react-style",
    }
}

use anyhow::Context;
