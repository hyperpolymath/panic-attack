// SPDX-License-Identifier: MPL-2.0

//! Cross-repo query subcommand (issue #33 S3).
//!
//! Evaluates a small S-expression query language over the persisted
//! per-finding hexads (issue #33 S1) plus campaign-state hexads
//! (issue #33 S2). Returns a list of `FindingHit`s the caller can render
//! as a table or JSON.
//!
//! ## Supported forms (S3 initial)
//!
//! ```text
//! (category UnsafeCode)
//! (rule-id PA004)
//! (severity Critical)
//! (repo <name-substring>)
//! (file <path-substring>)
//! (pr-state open | pr-filed | pr-merged | pr-closed | dismissed | nil)
//! (and <expr> <expr> ...)
//! (or  <expr> <expr> ...)
//! (not <expr>)
//! ```
//!
//! ## Deferred to S3 follow-ups
//!
//! - `(crosslang :from FFI :to ProofDrift)` — relational chain over the
//!   kanren cross-language fact base. Needs an integration with
//!   `src/kanren/crosslang.rs` that runs *after* the persistence layer
//!   is settled in S1/S2/S3 initial.
//! - `(diff :since 2026-04-12 :category PA022)` — temporal slicing by
//!   run id. Requires an explicit "since" cursor in the hexad store
//!   beyond `created_at` (e.g. a "baseline run id" marker).
//!
//! The initial form is enough to express the operational queries the
//! estate-sweep campaign actually needs day-to-day: "all PA001 of
//! Critical severity that don't have an open PR yet", "all dismissed
//! findings in repo foo", etc.

use crate::storage::{
    load_campaign_hexads, load_finding_hexads, CampaignSemantic, FindingSemantic,
};
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

// ===========================================================================
// AST
// ===========================================================================

/// A parsed query expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Match by `WeakPointCategory` Debug name (e.g. "UnsafeCode").
    Category(String),
    /// Match by canonical rule id (e.g. "PA004").
    RuleId(String),
    /// Match by severity label (case-insensitive: "critical"/"high"/etc).
    Severity(String),
    /// Substring-match the repo name.
    Repo(String),
    /// Substring-match the file path.
    File(String),
    /// Match by campaign state. `None` means "no campaign hexad yet".
    PrState(Option<String>),
    /// Conjunction.
    And(Vec<Query>),
    /// Disjunction.
    Or(Vec<Query>),
    /// Negation.
    Not(Box<Query>),
}

/// One match from a query run.
#[derive(Debug, Clone, Serialize)]
pub struct FindingHit {
    pub finding_id: String,
    pub repo_name: String,
    pub file: String,
    pub line: Option<u32>,
    pub category: String,
    pub rule_id: String,
    pub severity: String,
    pub description: String,
    pub campaign_state: Option<String>,
    pub pr_url: Option<String>,
}

// ===========================================================================
// Parser — small S-expression subset
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    Atom(String),
    String(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                while let Some(&ch) = chars.peek() {
                    chars.next();
                    if ch == '"' {
                        closed = true;
                        break;
                    }
                    if ch == '\\' {
                        if let Some(&esc) = chars.peek() {
                            chars.next();
                            s.push(match esc {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                '\\' => '\\',
                                '"' => '"',
                                other => other,
                            });
                            continue;
                        }
                    }
                    s.push(ch);
                }
                if !closed {
                    bail!("unterminated string literal");
                }
                tokens.push(Token::String(s));
            }
            ';' => {
                while let Some(&ch) = chars.peek() {
                    chars.next();
                    if ch == '\n' {
                        break;
                    }
                }
            }
            _ => {
                let mut atom = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_whitespace() || ch == '(' || ch == ')' {
                        break;
                    }
                    atom.push(ch);
                    chars.next();
                }
                tokens.push(Token::Atom(atom));
            }
        }
    }
    Ok(tokens)
}

/// Parse a query string into an AST.
pub fn parse(input: &str) -> Result<Query> {
    let tokens = tokenize(input)?;
    let mut cursor = 0;
    let q = parse_expr(&tokens, &mut cursor)?;
    skip_eof(&tokens, cursor)?;
    Ok(q)
}

fn skip_eof(tokens: &[Token], cursor: usize) -> Result<()> {
    if cursor < tokens.len() {
        bail!("extra tokens after query expression");
    }
    Ok(())
}

fn parse_expr(tokens: &[Token], cursor: &mut usize) -> Result<Query> {
    let Some(tok) = tokens.get(*cursor) else {
        bail!("unexpected end of query");
    };
    match tok {
        Token::LParen => {
            *cursor += 1;
            parse_form(tokens, cursor)
        }
        Token::RParen => bail!("unexpected ')'"),
        Token::Atom(_) | Token::String(_) => {
            bail!("query must be a list, got bare atom");
        }
    }
}

fn parse_form(tokens: &[Token], cursor: &mut usize) -> Result<Query> {
    let head = parse_atom(tokens, cursor)?;
    let head_lower = head.to_ascii_lowercase();
    match head_lower.as_str() {
        "category" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::Category(v))
        }
        "rule-id" | "ruleid" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::RuleId(v))
        }
        "severity" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::Severity(v))
        }
        "repo" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::Repo(v))
        }
        "file" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::File(v))
        }
        "pr-state" | "prstate" => {
            let v = parse_value(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            let val = if v.eq_ignore_ascii_case("nil") || v.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(v)
            };
            Ok(Query::PrState(val))
        }
        "and" => {
            let children = parse_children(tokens, cursor)?;
            if children.is_empty() {
                bail!("(and ...) requires at least one child");
            }
            Ok(Query::And(children))
        }
        "or" => {
            let children = parse_children(tokens, cursor)?;
            if children.is_empty() {
                bail!("(or ...) requires at least one child");
            }
            Ok(Query::Or(children))
        }
        "not" => {
            let child = parse_expr(tokens, cursor)?;
            close_paren(tokens, cursor)?;
            Ok(Query::Not(Box::new(child)))
        }
        other => bail!("unknown query head: {}", other),
    }
}

fn parse_atom(tokens: &[Token], cursor: &mut usize) -> Result<String> {
    let Some(tok) = tokens.get(*cursor) else {
        bail!("unexpected end of query");
    };
    let s = match tok {
        Token::Atom(s) => s.clone(),
        Token::String(s) => s.clone(),
        _ => bail!("expected atom"),
    };
    *cursor += 1;
    Ok(s)
}

fn parse_value(tokens: &[Token], cursor: &mut usize) -> Result<String> {
    let Some(tok) = tokens.get(*cursor) else {
        bail!("expected value");
    };
    let v = match tok {
        Token::Atom(s) | Token::String(s) => s.clone(),
        Token::LParen | Token::RParen => bail!("expected value, got list"),
    };
    *cursor += 1;
    Ok(v)
}

fn parse_children(tokens: &[Token], cursor: &mut usize) -> Result<Vec<Query>> {
    let mut out = Vec::new();
    loop {
        match tokens.get(*cursor) {
            Some(Token::RParen) => {
                *cursor += 1;
                return Ok(out);
            }
            Some(_) => out.push(parse_expr(tokens, cursor)?),
            None => bail!("missing ')'"),
        }
    }
}

fn close_paren(tokens: &[Token], cursor: &mut usize) -> Result<()> {
    match tokens.get(*cursor) {
        Some(Token::RParen) => {
            *cursor += 1;
            Ok(())
        }
        Some(other) => Err(anyhow!("expected ')', got {:?}", other)),
        None => Err(anyhow!("missing ')'")),
    }
}

// ===========================================================================
// Evaluation
// ===========================================================================

/// Snapshot of one finding pre-joined with its campaign state.
struct FindingRow {
    finding: FindingSemantic,
    campaign: Option<CampaignSemantic>,
}

fn load_rows(base_dir: &Path) -> Result<Vec<FindingRow>> {
    let finding_hexads = load_finding_hexads(base_dir)?;
    let mut campaign_hexads = load_campaign_hexads(base_dir)?;
    campaign_hexads.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    // Latest campaign event wins per finding_id.
    let mut latest: HashMap<String, CampaignSemantic> = HashMap::new();
    for h in campaign_hexads {
        if let Some(c) = h.semantic.campaign {
            latest.insert(c.finding_id.clone(), c);
        }
    }

    let mut rows = Vec::new();
    for h in finding_hexads {
        if let Some(f) = h.semantic.finding {
            let campaign = latest.get(&f.finding_id).cloned();
            rows.push(FindingRow {
                finding: f,
                campaign,
            });
        }
    }
    Ok(rows)
}

fn matches(query: &Query, row: &FindingRow) -> bool {
    match query {
        Query::Category(target) => row.finding.category.eq_ignore_ascii_case(target),
        Query::RuleId(target) => row.finding.rule_id.eq_ignore_ascii_case(target),
        Query::Severity(target) => row.finding.severity.eq_ignore_ascii_case(target),
        Query::Repo(needle) => row
            .finding
            .repo_name
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        Query::File(needle) => row
            .finding
            .file
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        Query::PrState(expected) => match (expected, row.campaign.as_ref()) {
            (None, None) => true,
            (Some(want), Some(c)) => c.state.eq_ignore_ascii_case(want),
            _ => false,
        },
        Query::And(children) => children.iter().all(|c| matches(c, row)),
        Query::Or(children) => children.iter().any(|c| matches(c, row)),
        Query::Not(inner) => !matches(inner, row),
    }
}

/// Execute a query against the persisted hexad store and return all
/// matching findings.
pub fn run(query: &Query, base_dir: &Path) -> Result<Vec<FindingHit>> {
    let rows = load_rows(base_dir)?;
    let mut hits = Vec::new();
    for row in rows {
        if matches(query, &row) {
            hits.push(FindingHit {
                finding_id: row.finding.finding_id.clone(),
                repo_name: row.finding.repo_name.clone(),
                file: row.finding.file.clone(),
                line: row.finding.line,
                category: row.finding.category.clone(),
                rule_id: row.finding.rule_id.clone(),
                severity: row.finding.severity.clone(),
                description: row.finding.description.clone(),
                campaign_state: row.campaign.as_ref().map(|c| c.state.clone()),
                pr_url: row.campaign.as_ref().and_then(|c| c.pr_url.clone()),
            });
        }
    }
    hits.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    Ok(hits)
}

/// Render hits as a fixed-width table.
pub fn render_table(hits: &[FindingHit]) -> String {
    if hits.is_empty() {
        return "No matches.\n".to_string();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{:<6} {:<10} {:<20} {:<40} STATE\n",
        "RULE", "SEVERITY", "REPO", "LOCATION"
    ));
    out.push_str(&"-".repeat(96));
    out.push('\n');
    for h in hits {
        let loc = format!(
            "{}:{}",
            h.file,
            h.line.map(|n| n.to_string()).unwrap_or_default()
        );
        let state = h.campaign_state.as_deref().unwrap_or("—");
        let loc_trunc: String = loc.chars().take(40).collect();
        let repo_trunc: String = h.repo_name.chars().take(20).collect();
        out.push_str(&format!(
            "{:<6} {:<10} {:<20} {:<40} {}\n",
            h.rule_id, h.severity, repo_trunc, loc_trunc, state
        ));
    }
    out
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign;
    use crate::storage::build_finding_hexads;
    use tempfile::tempdir;

    fn write_test_findings(dir: &std::path::Path) {
        use crate::assemblyline::{AssemblylineReport, RepoResult};
        use crate::types::{
            AssailReport, Language, ProgramStatistics, Severity, WeakPoint, WeakPointCategory,
        };
        use std::path::PathBuf;

        fn wp(file: &str, line: u32, cat: WeakPointCategory, sev: Severity) -> WeakPoint {
            WeakPoint {
                category: cat,
                location: Some(format!("{}:{}", file, line)),
                file: Some(file.to_string()),
                line: Some(line),
                severity: sev,
                description: "test".to_string(),
                recommended_attack: vec![],
                suppressed: false,
            }
        }
        fn assail(repo: &str, wps: Vec<WeakPoint>) -> AssailReport {
            AssailReport {
                schema_version: "2.5".to_string(),
                program_path: PathBuf::from(format!("/tmp/{}", repo)),
                language: Language::Rust,
                frameworks: vec![],
                weak_points: wps,
                statistics: ProgramStatistics::default(),
                file_statistics: vec![],
                recommended_attacks: vec![],
                dependency_graph: Default::default(),
                taint_matrix: Default::default(),
                migration_metrics: None,
                suppressed_count: 0,
            }
        }

        let report = AssemblylineReport {
            schema_version: "2.5".to_string(),
            created_at: "2026-05-26T00:00:00Z".to_string(),
            directory: PathBuf::from("/tmp"),
            repos_scanned: 2,
            repos_with_findings: 2,
            repos_skipped: 0,
            total_weak_points: 3,
            total_critical: 1,
            results: vec![
                RepoResult {
                    repo_path: PathBuf::from("/tmp/alpha"),
                    repo_name: "alpha".to_string(),
                    weak_point_count: 2,
                    critical_count: 1,
                    high_count: 1,
                    total_files: 1,
                    total_lines: 10,
                    error: None,
                    fingerprint: None,
                    report: Some(assail(
                        "alpha",
                        vec![
                            wp("src/a.rs", 1, WeakPointCategory::UnsafeCode, Severity::High),
                            wp(
                                "src/a.rs",
                                7,
                                WeakPointCategory::CryptoMisuse,
                                Severity::Critical,
                            ),
                        ],
                    )),
                },
                RepoResult {
                    repo_path: PathBuf::from("/tmp/beta"),
                    repo_name: "beta".to_string(),
                    weak_point_count: 1,
                    critical_count: 0,
                    high_count: 0,
                    total_files: 1,
                    total_lines: 10,
                    error: None,
                    fingerprint: None,
                    report: Some(assail(
                        "beta",
                        vec![wp(
                            "src/b.rs",
                            3,
                            WeakPointCategory::UnsafeCode,
                            Severity::Medium,
                        )],
                    )),
                },
            ],
        };
        let hexads = build_finding_hexads(&report).expect("build ok");
        let findings_dir = dir.join("hexads").join("findings");
        std::fs::create_dir_all(&findings_dir).unwrap();
        for (i, h) in hexads.iter().enumerate() {
            // Force unique filenames even when timestamps collide.
            std::fs::write(
                findings_dir.join(format!("h-{i}.json")),
                serde_json::to_string_pretty(h).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn parse_category() {
        let q = parse("(category UnsafeCode)").unwrap();
        assert_eq!(q, Query::Category("UnsafeCode".to_string()));
    }

    #[test]
    fn parse_rule_id() {
        let q = parse("(rule-id PA004)").unwrap();
        assert_eq!(q, Query::RuleId("PA004".to_string()));
    }

    #[test]
    fn parse_pr_state_nil() {
        let q = parse("(pr-state nil)").unwrap();
        assert_eq!(q, Query::PrState(None));
    }

    #[test]
    fn parse_and_combination() {
        let q = parse("(and (category UnsafeCode) (severity High))").unwrap();
        assert_eq!(
            q,
            Query::And(vec![
                Query::Category("UnsafeCode".to_string()),
                Query::Severity("High".to_string()),
            ])
        );
    }

    #[test]
    fn parse_not() {
        let q = parse("(not (severity Low))").unwrap();
        assert_eq!(q, Query::Not(Box::new(Query::Severity("Low".to_string()))));
    }

    #[test]
    fn parse_rejects_unknown_head() {
        assert!(parse("(bogus PA001)").is_err());
    }

    #[test]
    fn parse_rejects_bare_atom() {
        assert!(parse("PA001").is_err());
    }

    #[test]
    fn parse_rejects_unterminated() {
        assert!(parse("(category PA001").is_err());
    }

    #[test]
    fn run_category_filter() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(category UnsafeCode)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn run_severity_filter() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(severity Critical)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "CryptoMisuse");
    }

    #[test]
    fn run_repo_substring() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(repo alpha)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn run_and_combination() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(and (category UnsafeCode) (severity High))").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].repo_name, "alpha");
    }

    #[test]
    fn run_or_combination() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(or (severity Critical) (severity Medium))").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn run_not() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(not (severity Medium))").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn run_pr_state_nil_matches_unregistered() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // No campaign hexads yet — every finding has pr-state nil.
        let q = parse("(pr-state nil)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn run_pr_state_excludes_registered() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let finding_id = "finding:alpha:src/a.rs:1:UnsafeCode";
        campaign::register_pr(finding_id, "https://example.invalid/pr/1", dir.path()).unwrap();
        let q = parse("(pr-state nil)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 2, "the PR-filed finding is excluded");
        assert!(hits.iter().all(|h| h.finding_id != finding_id));
    }

    #[test]
    fn run_pr_state_filed_includes_only_registered() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let finding_id = "finding:alpha:src/a.rs:1:UnsafeCode";
        campaign::register_pr(finding_id, "https://example.invalid/pr/1", dir.path()).unwrap();
        let q = parse("(pr-state pr-filed)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].finding_id, finding_id);
        assert_eq!(
            hits[0].pr_url.as_deref(),
            Some("https://example.invalid/pr/1")
        );
    }

    #[test]
    fn render_table_empty() {
        let s = render_table(&[]);
        assert!(s.contains("No matches"));
    }

    #[test]
    fn render_table_basic() {
        let hits = vec![FindingHit {
            finding_id: "finding:demo:src/a.rs:1:UnsafeCode".to_string(),
            repo_name: "demo".to_string(),
            file: "src/a.rs".to_string(),
            line: Some(1),
            category: "UnsafeCode".to_string(),
            rule_id: "PA004".to_string(),
            severity: "high".to_string(),
            description: "test".to_string(),
            campaign_state: Some("pr-filed".to_string()),
            pr_url: Some("https://example.invalid".to_string()),
        }];
        let s = render_table(&hits);
        assert!(s.contains("PA004"));
        assert!(s.contains("demo"));
        assert!(s.contains("pr-filed"));
    }
}
