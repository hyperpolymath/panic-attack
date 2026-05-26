// SPDX-License-Identifier: MPL-2.0

//! Campaign-state orchestration (issue #33 S2).
//!
//! Tracks the lifecycle of individual findings emitted by the assemblyline
//! per-finding hexad path (issue #33 S1):
//!
//! - `register_pr(finding_id, pr_url)` — opens a PR for a finding.
//! - `dismiss(finding_id, reason)` — marks a finding parked / known-good /
//!   intentionally-out-of-scope.
//! - `status_markdown(base_dir)` — renders a Markdown tracker identical
//!   in shape to the manual checklist used in issue #32.
//!
//! State is persisted as campaign-facet hexads written under
//! `<base_dir>/hexads/campaign/`. The store is append-only: each call
//! writes a *new* hexad. `status` derives the current state per
//! `finding_id` by sorting all campaign hexads by `created_at` and
//! keeping the newest one for each subject.
//!
//! Polling GitHub for PR-state updates is deferred to a follow-up slice
//! (S2b) — this initial S2 focuses on the local lifecycle primitives so
//! the campaign data can accumulate before the polling logic lands.

use crate::storage::{
    build_campaign_hexad, load_campaign_hexads, load_finding_hexads, write_campaign_hexad,
    CampaignSemantic, PanicAttackHexad,
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;

/// Canonical state labels written into `CampaignSemantic.state`.
///
/// New variants can be added without breaking older readers — the field
/// is a `String` on the wire (forward-compatible by design).
pub mod state {
    pub const OPEN: &str = "open";
    pub const PR_FILED: &str = "pr-filed";
    pub const PR_MERGED: &str = "pr-merged";
    pub const PR_CLOSED: &str = "pr-closed";
    pub const DISMISSED: &str = "dismissed";
}

/// Register an open PR against a known finding.
///
/// Writes a `pr-filed` campaign hexad to `<base_dir>/hexads/campaign/`.
/// Returns the path written.
pub fn register_pr(finding_id: &str, pr_url: &str, base_dir: &Path) -> Result<std::path::PathBuf> {
    if finding_id.is_empty() {
        return Err(anyhow!("finding_id must not be empty"));
    }
    if pr_url.is_empty() {
        return Err(anyhow!("pr_url must not be empty"));
    }
    let hexad = build_campaign_hexad(CampaignSemantic {
        finding_id: finding_id.to_string(),
        state: state::PR_FILED.to_string(),
        pr_url: Some(pr_url.to_string()),
        reason: None,
        last_polled: None,
    });
    write_campaign_hexad(&hexad, base_dir)
}

/// Dismiss a finding (parked, known-good, out-of-scope).
///
/// Writes a `dismissed` campaign hexad. Returns the path written.
pub fn dismiss(finding_id: &str, reason: &str, base_dir: &Path) -> Result<std::path::PathBuf> {
    if finding_id.is_empty() {
        return Err(anyhow!("finding_id must not be empty"));
    }
    let hexad = build_campaign_hexad(CampaignSemantic {
        finding_id: finding_id.to_string(),
        state: state::DISMISSED.to_string(),
        pr_url: None,
        reason: Some(reason.to_string()),
        last_polled: None,
    });
    write_campaign_hexad(&hexad, base_dir)
}

/// One row of the campaign tracker — current state of a finding.
#[derive(Debug, Clone)]
pub struct CampaignRow {
    pub finding_id: String,
    pub state: String,
    pub pr_url: Option<String>,
    pub reason: Option<String>,
    pub last_event_at: String,
    /// If the finding hexad is available, its repo name (for display).
    pub repo_name: Option<String>,
    /// Same — rule id (e.g. PA004).
    pub rule_id: Option<String>,
    /// Same — file:line summary.
    pub location: Option<String>,
}

/// Compute the current campaign state for every finding seen, by
/// folding the append-only hexad stream by `finding_id` and keeping the
/// newest event.
pub fn current_state(base_dir: &Path) -> Result<Vec<CampaignRow>> {
    let mut campaign = load_campaign_hexads(base_dir)?;
    campaign.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    // Index finding metadata by finding_id (latest wins, but for findings
    // the schema is run-stable so any matching hexad will do).
    let findings = load_finding_hexads(base_dir)?;
    let mut finding_meta: HashMap<String, &PanicAttackHexad> = HashMap::new();
    for h in &findings {
        if let Some(f) = h.semantic.finding.as_ref() {
            finding_meta.insert(f.finding_id.clone(), h);
        }
    }

    let mut latest: HashMap<String, (String, CampaignSemantic)> = HashMap::new();
    for h in campaign {
        if let Some(c) = h.semantic.campaign.clone() {
            latest.insert(c.finding_id.clone(), (h.created_at.clone(), c));
        }
    }

    let mut rows: Vec<CampaignRow> = latest
        .into_iter()
        .map(|(_, (ts, c))| {
            let (repo_name, rule_id, location) = finding_meta
                .get(&c.finding_id)
                .and_then(|h| h.semantic.finding.as_ref())
                .map(|f| {
                    (
                        Some(f.repo_name.clone()),
                        Some(f.rule_id.clone()),
                        Some(format!(
                            "{}:{}",
                            f.file,
                            f.line.map(|n| n.to_string()).unwrap_or_default()
                        )),
                    )
                })
                .unwrap_or((None, None, None));
            CampaignRow {
                finding_id: c.finding_id,
                state: c.state,
                pr_url: c.pr_url,
                reason: c.reason,
                last_event_at: ts,
                repo_name,
                rule_id,
                location,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    Ok(rows)
}

/// Render a Markdown tracker matching the shape used by issue #32.
///
/// Rows sorted by `finding_id`; checkbox `[x]` for merged/closed/dismissed,
/// `[ ]` otherwise. State, PR link (or reason), and timestamp appear in
/// columns. An ungrouped "Findings without campaign state" footer is
/// omitted from S2 to keep the output small; S3 query is the right place
/// to list "open work not yet PR'd".
pub fn status_markdown(base_dir: &Path) -> Result<String> {
    let rows = current_state(base_dir)?;
    let now = Utc::now().to_rfc3339();
    let mut out = String::new();
    out.push_str(&format!(
        "# Campaign tracker — `panic-attack`\n\n_Generated {now}_\n\n"
    ));
    if rows.is_empty() {
        out.push_str("_No campaign state recorded yet._\n");
        return Ok(out);
    }

    let merged_count = rows
        .iter()
        .filter(|r| matches!(r.state.as_str(), state::PR_MERGED | state::PR_CLOSED))
        .count();
    let open_count = rows
        .iter()
        .filter(|r| matches!(r.state.as_str(), state::PR_FILED | state::OPEN))
        .count();
    let dismissed_count = rows.iter().filter(|r| r.state == state::DISMISSED).count();
    out.push_str(&format!(
        "**Summary**: {} merged/closed, {} open, {} dismissed (total {}).\n\n",
        merged_count,
        open_count,
        dismissed_count,
        rows.len()
    ));

    out.push_str("| ☐ | Finding | Repo | Rule | Location | State | PR / Reason | Last event |\n");
    out.push_str("|---|---------|------|------|----------|-------|-------------|------------|\n");
    for r in rows {
        let check = match r.state.as_str() {
            state::PR_MERGED | state::PR_CLOSED | state::DISMISSED => "[x]",
            _ => "[ ]",
        };
        let pr_or_reason = match (r.pr_url.as_deref(), r.reason.as_deref()) {
            (Some(url), _) => format!("[PR]({url})"),
            (None, Some(reason)) => reason.to_string(),
            (None, None) => "—".to_string(),
        };
        out.push_str(&format!(
            "| {} | `{}` | {} | {} | {} | {} | {} | {} |\n",
            check,
            r.finding_id,
            r.repo_name.as_deref().unwrap_or("—"),
            r.rule_id.as_deref().unwrap_or("—"),
            r.location.as_deref().unwrap_or("—"),
            r.state,
            pr_or_reason,
            r.last_event_at,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn register_pr_writes_hexad() {
        let dir = tempdir().unwrap();
        let path = register_pr(
            "finding:demo:src/a.rs:1:UnsafeCode",
            "https://example.invalid/pr/1",
            dir.path(),
        )
        .expect("register ok");
        assert!(path.exists());
        let rows = current_state(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, state::PR_FILED);
        assert_eq!(
            rows[0].pr_url.as_deref(),
            Some("https://example.invalid/pr/1")
        );
    }

    #[test]
    fn dismiss_overrides_open() {
        let dir = tempdir().unwrap();
        let id = "finding:demo:src/a.rs:1:UnsafeCode";
        register_pr(id, "https://example.invalid/pr/1", dir.path()).unwrap();
        // Sleep a hair to ensure the second hexad's created_at sorts strictly later.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        dismiss(id, "intentional sentinel", dir.path()).unwrap();
        let rows = current_state(dir.path()).unwrap();
        assert_eq!(rows.len(), 1, "one finding, latest state wins");
        assert_eq!(rows[0].state, state::DISMISSED);
        assert_eq!(rows[0].reason.as_deref(), Some("intentional sentinel"));
    }

    #[test]
    fn register_pr_rejects_empty_args() {
        let dir = tempdir().unwrap();
        assert!(register_pr("", "https://example.invalid", dir.path()).is_err());
        assert!(register_pr("finding:x:y:1:Z", "", dir.path()).is_err());
    }

    #[test]
    fn status_markdown_handles_empty() {
        let dir = tempdir().unwrap();
        let md = status_markdown(dir.path()).unwrap();
        assert!(md.contains("No campaign state recorded yet"));
    }

    #[test]
    fn status_markdown_renders_rows() {
        let dir = tempdir().unwrap();
        register_pr(
            "finding:alpha:src/a.rs:1:UnsafeCode",
            "https://example.invalid/pr/1",
            dir.path(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        dismiss(
            "finding:beta:src/b.rs:9:PanicPath",
            "test coverage gap",
            dir.path(),
        )
        .unwrap();
        let md = status_markdown(dir.path()).unwrap();
        assert!(md.contains("finding:alpha:src/a.rs:1:UnsafeCode"));
        assert!(md.contains("finding:beta:src/b.rs:9:PanicPath"));
        assert!(md.contains("pr-filed"));
        assert!(md.contains("dismissed"));
        assert!(md.contains("test coverage gap"));
        assert!(md.contains("1 open, 1 dismissed"));
    }
}
