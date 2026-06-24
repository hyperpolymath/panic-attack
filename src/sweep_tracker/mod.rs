// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Estate-sweep tracker — Markdown report generator (issue #33 follow-up).
//!
//! Produces a hierarchical issue-#32-style sweep tracker by joining the
//! per-finding hexad store (issue #33 S1) with the campaign-state hexad
//! store (issue #33 S2). This is a *report* over the same data the
//! per-finding `panic-attack campaign status` table renders, but
//! organised the way an estate sweep is run: top-down by repo, and a
//! cross-cut by category.
//!
//! Distinguishing features vs `campaign::status_markdown`:
//!
//! - **Hierarchical**, not flat: grouped by repo and/or category.
//! - **Estate summary** up top — count of repos, criticals, PRs filed,
//!   dismissed, and open-no-PR.
//! - **Always sourced from the finding store**: a finding with no
//!   campaign hexad still appears (state `open`); the per-finding
//!   table is campaign-driven and omits never-touched findings.
//! - **Deterministic**: repos alphabetically; findings within each
//!   repo by `(rule_id, file, line)`; categories by rule_id.
//!
//! The intended workflow:
//!
//! ```text
//! panic-attack sweep-tracker --output sweep-tracker.md
//! ```
//!
//! …producing a Markdown checklist that can be pasted into an
//! estate-sweep tracker issue (the issue-#32 shape).

use crate::storage::{load_campaign_hexads, load_finding_hexads, CampaignSemantic};
use anyhow::Result;
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Which sections of the report to emit.
///
/// `Both` is the default and renders a "By repo" section followed by a
/// "By category" section, with a shared estate-summary header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportShape {
    /// Group findings by repository name only.
    ByRepo,
    /// Group findings by category (rule id) only.
    ByCategory,
    /// Render both groupings, separated by an `## By category` heading.
    #[default]
    Both,
}

/// One finding joined against its current campaign state, if any.
#[derive(Debug, Clone)]
struct JoinedRow {
    repo_name: String,
    file: String,
    line: Option<u32>,
    rule_id: String,
    category: String,
    severity: String,
    finding_id: String,
    /// Current campaign state. `"open"` if no campaign hexad exists.
    state: String,
    pr_url: Option<String>,
    dismissal_reason: Option<String>,
}

impl JoinedRow {
    fn is_pr_filed(&self) -> bool {
        matches!(
            self.state.as_str(),
            crate::campaign::state::PR_FILED
                | crate::campaign::state::PR_MERGED
                | crate::campaign::state::PR_CLOSED
        )
    }

    fn is_dismissed(&self) -> bool {
        self.state == crate::campaign::state::DISMISSED
    }

    fn is_done(&self) -> bool {
        matches!(
            self.state.as_str(),
            crate::campaign::state::PR_MERGED
                | crate::campaign::state::PR_CLOSED
                | crate::campaign::state::DISMISSED
        )
    }

    fn is_open(&self) -> bool {
        self.state == crate::campaign::state::OPEN
    }

    fn is_critical(&self) -> bool {
        self.severity.eq_ignore_ascii_case("critical")
    }

    fn is_high(&self) -> bool {
        self.severity.eq_ignore_ascii_case("high")
    }

    /// Stable per-row sort key: `(rule_id, file, line)`. Ties broken by
    /// finding_id so the order is fully deterministic.
    fn sort_key(&self) -> (String, String, u32, String) {
        (
            self.rule_id.clone(),
            self.file.clone(),
            self.line.unwrap_or(0),
            self.finding_id.clone(),
        )
    }
}

/// Build the joined finding × campaign-state rows for `base_dir`.
///
/// One row per finding hexad. Latest campaign hexad per `finding_id`
/// wins (matching `campaign::current_state`). Returned in unspecified
/// order; the renderer sorts per section.
fn collect_rows(base_dir: &Path) -> Result<Vec<JoinedRow>> {
    let finding_hexads = load_finding_hexads(base_dir)?;
    let mut campaign_hexads = load_campaign_hexads(base_dir)?;
    campaign_hexads.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    // Newest campaign hexad per finding_id wins.
    let mut latest_state: HashMap<String, CampaignSemantic> = HashMap::new();
    for h in &campaign_hexads {
        if let Some(c) = h.semantic.campaign.as_ref() {
            latest_state.insert(c.finding_id.clone(), c.clone());
        }
    }

    let mut rows = Vec::new();
    for h in &finding_hexads {
        let Some(f) = h.semantic.finding.as_ref() else {
            continue;
        };
        let (state, pr_url, dismissal_reason) = latest_state
            .get(&f.finding_id)
            .map(|c| (c.state.clone(), c.pr_url.clone(), c.reason.clone()))
            .unwrap_or_else(|| (crate::campaign::state::OPEN.to_string(), None, None));
        rows.push(JoinedRow {
            repo_name: f.repo_name.clone(),
            file: f.file.clone(),
            line: f.line,
            rule_id: f.rule_id.clone(),
            category: f.category.clone(),
            severity: f.severity.clone(),
            finding_id: f.finding_id.clone(),
            state,
            pr_url,
            dismissal_reason,
        });
    }
    Ok(rows)
}

/// Estate-wide summary counts for the header.
#[derive(Debug, Clone, Default)]
struct Summary {
    total: usize,
    repos: usize,
    critical: usize,
    high: usize,
    pr_filed: usize,
    dismissed: usize,
    open: usize,
}

impl Summary {
    fn from_rows(rows: &[JoinedRow]) -> Self {
        let mut repos: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut s = Summary {
            total: rows.len(),
            ..Default::default()
        };
        for r in rows {
            repos.insert(r.repo_name.as_str());
            if r.is_critical() {
                s.critical += 1;
            }
            if r.is_high() {
                s.high += 1;
            }
            if r.is_pr_filed() {
                s.pr_filed += 1;
            }
            if r.is_dismissed() {
                s.dismissed += 1;
            }
            if r.is_open() {
                s.open += 1;
            }
        }
        s.repos = repos.len();
        s
    }
}

/// Render one row's trailing state/pr/reason marker, e.g.
/// `pr-merged ([#42](https://...))`, `dismissed (test scaffold)`, or
/// `open`.
fn render_state_marker(row: &JoinedRow) -> String {
    if let Some(url) = row.pr_url.as_deref() {
        // Best-effort `#<num>` extraction for compactness; falls back to
        // the URL itself when the trailing segment isn't a number.
        let label = pr_number_label(url).unwrap_or_else(|| url.to_string());
        format!("{} ([{}]({}))", row.state, label, url)
    } else if let Some(reason) = row.dismissal_reason.as_deref() {
        format!("{} ({})", row.state, reason)
    } else {
        row.state.clone()
    }
}

/// Extract a `#<num>` label from a PR URL like
/// `https://github.com/org/repo/pull/42`. Returns `None` when the URL
/// doesn't end in a numeric path segment.
fn pr_number_label(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next()?;
    let num: u64 = tail.parse().ok()?;
    Some(format!("#{}", num))
}

/// `file:line` shorthand for inline display.
fn location_str(row: &JoinedRow) -> String {
    match row.line {
        Some(n) if n > 0 => format!("{}:{}", row.file, n),
        _ => row.file.clone(),
    }
}

fn checkbox(row: &JoinedRow) -> &'static str {
    if row.is_done() {
        "[x]"
    } else {
        "[ ]"
    }
}

fn render_by_repo_section(rows: &[JoinedRow]) -> String {
    let mut by_repo: BTreeMap<String, Vec<&JoinedRow>> = BTreeMap::new();
    for r in rows {
        by_repo.entry(r.repo_name.clone()).or_default().push(r);
    }

    let mut out = String::new();
    out.push_str("## By repo\n\n");
    if by_repo.is_empty() {
        out.push_str("_No findings recorded._\n\n");
        return out;
    }
    for (repo, mut repo_rows) in by_repo {
        repo_rows.sort_by_key(|r| r.sort_key());
        let critical = repo_rows.iter().filter(|r| r.is_critical()).count();
        out.push_str(&format!(
            "### {} ({} findings, {} critical)\n\n",
            repo,
            repo_rows.len(),
            critical,
        ));
        for r in repo_rows {
            out.push_str(&format!(
                "- {} {} {} — {}\n",
                checkbox(r),
                r.rule_id,
                location_str(r),
                render_state_marker(r),
            ));
        }
        out.push('\n');
    }
    out
}

fn render_by_category_section(rows: &[JoinedRow]) -> String {
    let mut by_category: BTreeMap<(String, String), Vec<&JoinedRow>> = BTreeMap::new();
    for r in rows {
        by_category
            .entry((r.rule_id.clone(), r.category.clone()))
            .or_default()
            .push(r);
    }

    let mut out = String::new();
    out.push_str("## By category\n\n");
    if by_category.is_empty() {
        out.push_str("_No findings recorded._\n\n");
        return out;
    }
    for ((rule_id, category), mut cat_rows) in by_category {
        cat_rows.sort_by_key(|r| (r.repo_name.clone(), r.sort_key()));
        let repo_set: std::collections::BTreeSet<&str> =
            cat_rows.iter().map(|r| r.repo_name.as_str()).collect();
        out.push_str(&format!(
            "### {} {} ({} findings across {} repos)\n\n",
            rule_id,
            category,
            cat_rows.len(),
            repo_set.len(),
        ));
        for r in cat_rows {
            out.push_str(&format!(
                "- {} {} {} — {}\n",
                checkbox(r),
                r.repo_name,
                location_str(r),
                render_state_marker(r),
            ));
        }
        out.push('\n');
    }
    out
}

fn render_header(rows: &[JoinedRow]) -> String {
    let now = Utc::now().to_rfc3339();
    let s = Summary::from_rows(rows);
    let mut out = String::new();
    out.push_str("# Estate sweep tracker\n\n");
    out.push_str(&format!("_Generated {}_\n\n", now));
    if s.total == 0 {
        out.push_str("_No findings recorded yet — the per-finding hexad store is empty._\n\n");
        return out;
    }
    out.push_str(&format!(
        "**Estate summary**: {} findings across {} repos ({} critical, {} high). \
         {} PR-filed, {} dismissed, {} open (no PR).\n\n",
        s.total, s.repos, s.critical, s.high, s.pr_filed, s.dismissed, s.open,
    ));
    out
}

/// Render an estate-sweep tracker Markdown report.
///
/// Reads the per-finding and campaign hexad stores under `base_dir`,
/// joins them, and emits a Markdown document shaped after the
/// issue-#32 tracker checklist.
pub fn render_report(base_dir: &Path, shape: ReportShape) -> Result<String> {
    let rows = collect_rows(base_dir)?;
    let mut out = render_header(&rows);
    if rows.is_empty() {
        // Header already announced the empty-store case; skip per-section
        // headings entirely so the document doesn't carry confusing
        // "## By repo / _No findings recorded._" stanzas.
        return Ok(out);
    }
    match shape {
        ReportShape::ByRepo => out.push_str(&render_by_repo_section(&rows)),
        ReportShape::ByCategory => out.push_str(&render_by_category_section(&rows)),
        ReportShape::Both => {
            out.push_str(&render_by_repo_section(&rows));
            out.push_str(&render_by_category_section(&rows));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign;
    use crate::storage::{
        CampaignSemantic, FindingSemantic, HexadProvenance, HexadSemantic, PanicAttackHexad,
    };
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_finding_hexad(base_dir: &Path, finding: FindingSemantic) -> PathBuf {
        let dir = base_dir.join("hexads").join("findings");
        fs::create_dir_all(&dir).unwrap();
        // Sanitise filename-hostile chars from the finding id; the on-disk
        // hexad id is decorative (the join key lives in `semantic.finding`).
        let safe_id: String = finding
            .finding_id
            .chars()
            .map(|c| {
                if matches!(c, ':' | '/' | '\\') {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        let id = format!("pa-finding-test-{}", safe_id);
        let hexad = PanicAttackHexad {
            schema: "verisimdb.hexad.v1".to_string(),
            id: id.clone(),
            created_at: "2026-05-26T12:00:00Z".to_string(),
            provenance: HexadProvenance {
                tool: "panic-attack".to_string(),
                version: "test".to_string(),
                program_path: format!("/tmp/{}", finding.repo_name),
                language: "Rust".to_string(),
                attestation_hash: None,
            },
            semantic: HexadSemantic {
                total_weak_points: 1,
                critical_count: if finding.severity == "critical" { 1 } else { 0 },
                high_count: if finding.severity == "high" { 1 } else { 0 },
                total_crashes: 0,
                robustness_score: 0.0,
                categories: vec![finding.category.clone()],
                migration: None,
                finding: Some(finding),
                campaign: None,
                crosslang: None,
            },
            document: serde_json::Value::Null,
        };
        let path = dir.join(format!("{}.json", id));
        fs::write(&path, serde_json::to_string_pretty(&hexad).unwrap()).unwrap();
        path
    }

    fn write_campaign_hexad_with_id(base_dir: &Path, id: &str, semantic: CampaignSemantic) {
        let dir = base_dir.join("hexads").join("campaign");
        fs::create_dir_all(&dir).unwrap();
        let hexad = PanicAttackHexad {
            schema: "verisimdb.hexad.v1".to_string(),
            id: id.to_string(),
            created_at: format!("2026-05-26T12:00:{:02}Z", id.len() % 60),
            provenance: HexadProvenance {
                tool: "panic-attack".to_string(),
                version: "test".to_string(),
                program_path: "campaign".to_string(),
                language: "n/a".to_string(),
                attestation_hash: None,
            },
            semantic: HexadSemantic {
                total_weak_points: 0,
                critical_count: 0,
                high_count: 0,
                total_crashes: 0,
                robustness_score: 0.0,
                categories: Vec::new(),
                migration: None,
                finding: None,
                campaign: Some(semantic),
                crosslang: None,
            },
            document: serde_json::Value::Null,
        };
        let path = dir.join(format!("{}.json", id));
        fs::write(&path, serde_json::to_string_pretty(&hexad).unwrap()).unwrap();
    }

    fn sample_finding(
        repo: &str,
        file: &str,
        line: u32,
        rule_id: &str,
        category: &str,
        severity: &str,
    ) -> FindingSemantic {
        FindingSemantic {
            finding_id: format!("finding:{}:{}:{}:{}", repo, file, line, category),
            repo_name: repo.to_string(),
            file: file.to_string(),
            line: Some(line),
            category: category.to_string(),
            rule_id: rule_id.to_string(),
            rule_name: rule_id.to_lowercase(),
            severity: severity.to_string(),
            description: format!("sample finding {}:{}:{}", repo, file, line),
            first_seen_run: "run-test".to_string(),
            last_seen_run: "run-test".to_string(),
            framework: None,
        }
    }

    #[test]
    fn empty_store_yields_empty_marker() {
        let dir = tempdir().unwrap();
        let report = render_report(dir.path(), ReportShape::Both).unwrap();
        assert!(report.starts_with("# Estate sweep tracker"));
        assert!(report.contains("_No findings recorded yet"));
        // Neither section should appear when there are no findings.
        assert!(!report.contains("## By repo"));
        assert!(!report.contains("## By category"));
    }

    #[test]
    fn by_repo_groups_and_summarises() {
        let dir = tempdir().unwrap();
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/lib.rs", 23, "PA001", "PanicPath", "critical"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/ffi.rs", 7, "PA004", "UnsafeCode", "high"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("beta", "src/auth.rs", 91, "PA022", "CryptoMisuse", "medium"),
        );

        let report = render_report(dir.path(), ReportShape::ByRepo).unwrap();
        assert!(report.contains("**Estate summary**: 3 findings across 2 repos"));
        assert!(report.contains("(1 critical, 1 high)"));
        assert!(report.contains("## By repo"));
        assert!(report.contains("### alpha (2 findings, 1 critical)"));
        assert!(report.contains("### beta (1 findings, 0 critical)"));
        // Section absent when shape is ByRepo only.
        assert!(!report.contains("## By category"));

        // Deterministic ordering: alpha before beta, and within alpha the
        // PA001 finding sorts before PA004 (rule_id ascending).
        let alpha_idx = report.find("### alpha").unwrap();
        let beta_idx = report.find("### beta").unwrap();
        assert!(alpha_idx < beta_idx);
        let pa001_idx = report.find("PA001 src/lib.rs:23").unwrap();
        let pa004_idx = report.find("PA004 src/ffi.rs:7").unwrap();
        assert!(pa001_idx < pa004_idx);
    }

    #[test]
    fn by_category_groups_across_repos() {
        let dir = tempdir().unwrap();
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/a.rs", 1, "PA004", "UnsafeCode", "high"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("beta", "src/b.rs", 2, "PA004", "UnsafeCode", "high"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/c.rs", 3, "PA001", "PanicPath", "medium"),
        );

        let report = render_report(dir.path(), ReportShape::ByCategory).unwrap();
        assert!(report.contains("## By category"));
        assert!(report.contains("### PA001 PanicPath (1 findings across 1 repos)"));
        assert!(report.contains("### PA004 UnsafeCode (2 findings across 2 repos)"));
        assert!(!report.contains("## By repo"));

        // PA001 sorts before PA004.
        let pa001 = report.find("### PA001").unwrap();
        let pa004 = report.find("### PA004").unwrap();
        assert!(pa001 < pa004);
    }

    #[test]
    fn campaign_state_join_renders_pr_url_and_dismissal() {
        let dir = tempdir().unwrap();

        let pr_finding =
            sample_finding("alpha", "src/lib.rs", 23, "PA001", "PanicPath", "critical");
        let pr_finding_id = pr_finding.finding_id.clone();
        write_finding_hexad(dir.path(), pr_finding);

        let dismissed_finding = sample_finding(
            "alpha",
            "src/auth.rs",
            91,
            "PA022",
            "CryptoMisuse",
            "medium",
        );
        let dismissed_id = dismissed_finding.finding_id.clone();
        write_finding_hexad(dir.path(), dismissed_finding);

        let open_finding = sample_finding("alpha", "src/ffi.rs", 7, "PA004", "UnsafeCode", "high");
        write_finding_hexad(dir.path(), open_finding);

        // Manual write of campaign hexads to bypass timestamp collisions
        // (two same-millisecond calls to `build_campaign_hexad` would
        // produce identical hexad ids and the second would overwrite the
        // first on disk). Each gets a deterministic, unique id here.
        write_campaign_hexad_with_id(
            dir.path(),
            "pa-campaign-test-1",
            CampaignSemantic {
                finding_id: pr_finding_id.clone(),
                state: campaign::state::PR_MERGED.to_string(),
                pr_url: Some("https://github.com/example/alpha/pull/42".to_string()),
                reason: None,
                last_polled: None,
            },
        );

        write_campaign_hexad_with_id(
            dir.path(),
            "pa-campaign-test-2",
            CampaignSemantic {
                finding_id: dismissed_id.clone(),
                state: campaign::state::DISMISSED.to_string(),
                pr_url: None,
                reason: Some("test scaffold".to_string()),
                last_polled: None,
            },
        );

        let report = render_report(dir.path(), ReportShape::ByRepo).unwrap();

        // Estate summary: 1 PR-filed (counts pr-merged too), 1 dismissed, 1 open.
        assert!(report.contains("1 PR-filed, 1 dismissed, 1 open"));

        // PR row: checkbox ticked, state + GitHub-style #42 link.
        assert!(report.contains(
            "[x] PA001 src/lib.rs:23 — pr-merged ([#42](https://github.com/example/alpha/pull/42))"
        ));
        // Dismissal row: ticked, reason in parens.
        assert!(report.contains("[x] PA022 src/auth.rs:91 — dismissed (test scaffold)"));
        // Open row: empty checkbox, bare `open` marker.
        assert!(report.contains("[ ] PA004 src/ffi.rs:7 — open"));
    }

    #[test]
    fn deterministic_ordering_within_repo() {
        // Insert findings in a deliberately scrambled order; expect the
        // report to sort them by (rule_id, file, line).
        let dir = tempdir().unwrap();
        write_finding_hexad(
            dir.path(),
            sample_finding("zzz", "src/z.rs", 9, "PA004", "UnsafeCode", "low"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/b.rs", 5, "PA001", "PanicPath", "low"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/a.rs", 5, "PA001", "PanicPath", "low"),
        );
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/a.rs", 3, "PA001", "PanicPath", "low"),
        );

        let report = render_report(dir.path(), ReportShape::ByRepo).unwrap();

        // Repos: alpha before zzz.
        let alpha = report.find("### alpha").unwrap();
        let zzz = report.find("### zzz").unwrap();
        assert!(alpha < zzz);

        // Within alpha: a.rs:3 < a.rs:5 < b.rs:5.
        let a3 = report.find("PA001 src/a.rs:3").unwrap();
        let a5 = report.find("PA001 src/a.rs:5").unwrap();
        let b5 = report.find("PA001 src/b.rs:5").unwrap();
        assert!(a3 < a5);
        assert!(a5 < b5);
    }

    #[test]
    fn both_shape_emits_repo_then_category() {
        let dir = tempdir().unwrap();
        write_finding_hexad(
            dir.path(),
            sample_finding("alpha", "src/a.rs", 1, "PA004", "UnsafeCode", "high"),
        );
        let report = render_report(dir.path(), ReportShape::Both).unwrap();
        let repo_idx = report.find("## By repo").unwrap();
        let cat_idx = report.find("## By category").unwrap();
        assert!(repo_idx < cat_idx);
        // Header still present.
        assert!(report.contains("**Estate summary**"));
    }

    #[test]
    fn pr_number_label_handles_non_numeric_tail() {
        assert_eq!(
            pr_number_label("https://github.com/foo/bar/pull/42"),
            Some("#42".to_string())
        );
        assert_eq!(
            pr_number_label("https://github.com/foo/bar/pull/42/"),
            Some("#42".to_string())
        );
        assert_eq!(pr_number_label("https://example.invalid/some/path"), None);
        assert_eq!(pr_number_label(""), None);
    }
}
