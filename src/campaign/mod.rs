// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

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

/// Write an arbitrary state transition hexad.
///
/// Lower-level than `register_pr` / `dismiss` — callers supply the full
/// state, optional PR url, and optional reason. Used by `poll` to
/// promote a finding from `pr-filed` to `pr-merged` / `pr-closed`.
#[allow(dead_code)]
pub fn transition(
    finding_id: &str,
    new_state: &str,
    pr_url: Option<&str>,
    reason: Option<&str>,
    base_dir: &Path,
) -> Result<std::path::PathBuf> {
    if finding_id.is_empty() {
        return Err(anyhow!("finding_id must not be empty"));
    }
    if new_state.is_empty() {
        return Err(anyhow!("state must not be empty"));
    }
    let hexad = build_campaign_hexad(CampaignSemantic {
        finding_id: finding_id.to_string(),
        state: new_state.to_string(),
        pr_url: pr_url.map(str::to_string),
        reason: reason.map(str::to_string),
        last_polled: Some(Utc::now().to_rfc3339()),
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

// ---------------------------------------------------------------------------
// Issue #33 S2b — poll GitHub for PR state transitions
//
// The whole section is `#[cfg(feature = "http")]`: it depends on ureq
// (an optional dep) and on having any networking surface compiled in.
// ---------------------------------------------------------------------------

/// Parsed GitHub PR URL components.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPrUrl {
    pub owner: String,
    pub repo: String,
    pub number: u64,
}

/// Parse a GitHub PR URL into `(owner, repo, number)`.
///
/// Accepts the canonical form `https://github.com/<owner>/<repo>/pull/<n>`
/// (with optional trailing slash or fragment).
#[cfg(feature = "http")]
pub fn parse_pr_url(url: &str) -> Result<ParsedPrUrl> {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .ok_or_else(|| anyhow!("not a github.com URL: {}", url))?;
    let mut parts = after_scheme
        .trim_end_matches('/')
        .split('/')
        .filter(|s| !s.is_empty());
    let owner = parts
        .next()
        .ok_or_else(|| anyhow!("missing owner in PR URL: {}", url))?
        .to_string();
    let repo = parts
        .next()
        .ok_or_else(|| anyhow!("missing repo in PR URL: {}", url))?
        .to_string();
    let kind = parts
        .next()
        .ok_or_else(|| anyhow!("missing 'pull' in PR URL: {}", url))?;
    if kind != "pull" {
        return Err(anyhow!("expected 'pull' segment, got '{}'", kind));
    }
    let number_str = parts
        .next()
        .ok_or_else(|| anyhow!("missing PR number in URL: {}", url))?;
    let number_only = number_str.split('#').next().unwrap_or(number_str);
    let number: u64 = number_only
        .parse()
        .map_err(|_| anyhow!("PR number is not a positive integer: {}", number_str))?;
    Ok(ParsedPrUrl {
        owner,
        repo,
        number,
    })
}

/// State derived from a GitHub PR API response.
#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePrState {
    /// PR is still open on GitHub.
    Open,
    /// PR was closed and merged.
    Merged,
    /// PR was closed without being merged.
    Closed,
}

#[cfg(feature = "http")]
impl RemotePrState {
    /// Canonical campaign state label for this remote state.
    pub fn campaign_state(self) -> &'static str {
        match self {
            RemotePrState::Open => state::PR_FILED,
            RemotePrState::Merged => state::PR_MERGED,
            RemotePrState::Closed => state::PR_CLOSED,
        }
    }
}

/// Result of a single poll iteration.
#[cfg(feature = "http")]
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PollOutcome {
    pub finding_id: String,
    pub pr_url: String,
    pub old_state: String,
    pub new_state: String,
    /// True when a new campaign hexad was written.
    pub transitioned: bool,
}

/// Decide whether a remote-fetched state warrants writing a new
/// transition hexad. Pure — testable without network.
#[cfg(feature = "http")]
pub fn should_transition(current: &str, remote: RemotePrState) -> bool {
    let target = remote.campaign_state();
    !current.eq_ignore_ascii_case(target)
}

/// Poll GitHub for PR state and write transition hexads.
///
/// For each finding whose latest campaign state is `pr-filed`, fetch
/// the PR's current state via the GitHub REST API and — if it has
/// changed — write a new campaign hexad (`pr-merged` / `pr-closed`).
///
/// Auth: reads `GH_TOKEN` then `GITHUB_TOKEN` from the environment;
/// unauthenticated calls are accepted but capped at 60/hour by GitHub.
#[cfg(feature = "http")]
pub fn poll(base_dir: &Path) -> Result<Vec<PollOutcome>> {
    let rows = current_state(base_dir)?;
    let mut outcomes = Vec::new();
    for row in rows {
        if row.state != state::PR_FILED {
            continue;
        }
        let Some(ref url) = row.pr_url else { continue };
        let parsed = match parse_pr_url(url) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let remote = match fetch_remote_pr_state(&parsed) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let old_state = row.state.clone();
        let new_state_label = remote.campaign_state().to_string();
        let transitioned = should_transition(&row.state, remote);
        if transitioned {
            transition(
                &row.finding_id,
                remote.campaign_state(),
                Some(url),
                None,
                base_dir,
            )?;
        }
        outcomes.push(PollOutcome {
            finding_id: row.finding_id,
            pr_url: url.clone(),
            old_state,
            new_state: new_state_label,
            transitioned,
        });
    }
    Ok(outcomes)
}

/// Issue a single GET to the GitHub PR endpoint and map the response.
#[cfg(feature = "http")]
fn fetch_remote_pr_state(parsed: &ParsedPrUrl) -> Result<RemotePrState> {
    use std::io::Read;

    let url = format!(
        "https://api.github.com/repos/{}/{}/pulls/{}",
        parsed.owner, parsed.repo, parsed.number
    );
    let mut builder = ureq::get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "panic-attack-campaign-poll")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Ok(token) = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")) {
        if !token.is_empty() {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }
    }
    let mut response = builder
        .call()
        .map_err(|e| anyhow!("GitHub API request failed: {}", e))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(anyhow!("GitHub API returned {}", status));
    }
    let mut body = String::new();
    response
        .body_mut()
        .as_reader()
        .take(4 * 1024 * 1024)
        .read_to_string(&mut body)
        .map_err(|e| anyhow!("reading GitHub PR response: {}", e))?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| anyhow!("parsing GitHub PR response: {}", e))?;
    let state_field = json.get("state").and_then(|v| v.as_str()).unwrap_or("");
    let merged_at = json.get("merged_at").and_then(|v| v.as_str());
    let merged = json
        .get("merged")
        .and_then(|v| v.as_bool())
        .unwrap_or(merged_at.is_some());
    Ok(match (state_field, merged) {
        (_, true) => RemotePrState::Merged,
        ("closed", false) => RemotePrState::Closed,
        _ => RemotePrState::Open,
    })
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

    // ----- Issue #33 S2b: poll-related tests -------------------------------

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_canonical() {
        let p = parse_pr_url("https://github.com/foo/bar/pull/42").unwrap();
        assert_eq!(p.owner, "foo");
        assert_eq!(p.repo, "bar");
        assert_eq!(p.number, 42);
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_trailing_slash() {
        let p = parse_pr_url("https://github.com/foo/bar/pull/42/").unwrap();
        assert_eq!(p.number, 42);
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_with_fragment() {
        let p = parse_pr_url("https://github.com/foo/bar/pull/42#discussion_r1").unwrap();
        assert_eq!(p.number, 42);
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_rejects_non_github() {
        assert!(parse_pr_url("https://gitlab.com/foo/bar/pull/42").is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_rejects_issue_url() {
        assert!(parse_pr_url("https://github.com/foo/bar/issues/42").is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn parse_pr_url_rejects_missing_number() {
        assert!(parse_pr_url("https://github.com/foo/bar/pull/").is_err());
        assert!(parse_pr_url("https://github.com/foo/bar/pull/abc").is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn should_transition_open_to_filed_is_noop() {
        assert!(!should_transition(state::PR_FILED, RemotePrState::Open));
    }

    #[cfg(feature = "http")]
    #[test]
    fn should_transition_filed_to_merged() {
        assert!(should_transition(state::PR_FILED, RemotePrState::Merged));
    }

    #[cfg(feature = "http")]
    #[test]
    fn should_transition_filed_to_closed() {
        assert!(should_transition(state::PR_FILED, RemotePrState::Closed));
    }

    #[cfg(feature = "http")]
    #[test]
    fn should_transition_already_merged_is_noop() {
        assert!(!should_transition(state::PR_MERGED, RemotePrState::Merged));
    }

    #[test]
    fn transition_writes_new_hexad() {
        let dir = tempdir().unwrap();
        let finding_id = "finding:demo:src/a.rs:1:UnsafeCode";
        register_pr(finding_id, "https://github.com/x/y/pull/1", dir.path()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        transition(
            finding_id,
            state::PR_MERGED,
            Some("https://github.com/x/y/pull/1"),
            None,
            dir.path(),
        )
        .unwrap();
        let rows = current_state(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, state::PR_MERGED);
    }

    #[test]
    fn transition_rejects_empty_args() {
        let dir = tempdir().unwrap();
        assert!(transition("", state::PR_MERGED, None, None, dir.path()).is_err());
        assert!(transition("finding:x:y:1:Z", "", None, None, dir.path()).is_err());
    }
}
