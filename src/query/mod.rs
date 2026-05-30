// SPDX-License-Identifier: MPL-2.0

//! Cross-repo query subcommand (issue #33 S3).
//!
//! Evaluates a small S-expression query language over the persisted
//! per-finding hexads (issue #33 S1) plus campaign-state hexads
//! (issue #33 S2). Returns a list of `FindingHit`s the caller can render
//! as a table or JSON.
//!
//! ## Supported forms
//!
//! ```text
//! (category UnsafeCode)
//! (category PA004)                 ; auto-routes to (rule-id PA004)
//! (rule-id PA004)
//! (severity Critical)
//! (repo <name-substring>)
//! (file <path-substring>)
//! (pr-state open | pr-filed | pr-merged | pr-closed | dismissed | nil)
//! (since 2026-04-12)               ; or (since "2026-04-12T00:00:00Z")
//! (crosslang :from FFI :to ProofDrift)
//! (crosslang FFI ProofDrift)       ; positional shorthand
//! (and <expr> <expr> ...)
//! (or  <expr> <expr> ...)
//! (not <expr>)
//! (diff :since DATE :category C ...)   ; sugar for (and (since DATE) (category C) ...)
//! ```
//!
//! ### Inline keyword args on unary heads
//!
//! Any unary head (`category`, `rule-id`, `severity`, `repo`, `file`,
//! `pr-state`, `since`) accepts trailing `:keyword VALUE` pairs that are
//! desugared into an `(and ...)` conjunction with the positional clause.
//! This makes the issue #33 examples parse verbatim:
//!
//! ```text
//! (category PA001 :severity Critical :pr-state nil)
//!   ≡ (and (rule-id PA001) (severity Critical) (pr-state nil))
//!
//! (diff :since 2026-04-12 :category PA022)
//!   ≡ (and (since 2026-04-12) (rule-id PA022))
//! ```
//!
//! ## Semantic notes
//!
//! - `(since ...)` compares the finding's `first_seen_run` (when it
//!   parses as ISO-8601) or its hexad `created_at` against the cutoff
//!   lexicographically. RFC-3339 / ISO-8601 strings sort correctly under
//!   string comparison, which is what we use.
//!
//! - `(crosslang :from X :to Y)` is evaluated in two modes:
//!     * **Facts-backed** (`<dir>/hexads/crosslang/` is non-empty):
//!       matches a `Y`-category finding when there exists a persisted
//!       kanren-derived `CrossLangInteraction` in the same repo where one
//!       endpoint of the interaction is the file of an `X`-category
//!       finding. This is the "real" FFI/cross-language reachability
//!       semantics.
//!     * **Co-occurrence proxy** (fallback when no crosslang hexads are
//!       on disk): matches a `Y`-category finding in any repo that also
//!       has ≥ 1 `X`-category finding. Preserves the historical
//!       co-occurrence behaviour for users who haven't enabled crosslang
//!       persistence yet (`PANIC_ATTACK_STORE_CROSSLANG_HEXADS=1`).
//!
//!   Most FFI-driven proof drift surfaces in the same repo, so both
//!   modes converge on the operationally common case, but the
//!   facts-backed mode prunes cross-repo false-positive co-occurrences
//!   (e.g. an `UnsafeFFI`-bearing repo that contains an unrelated
//!   `ProofDrift` finding in a non-FFI module).

use crate::storage::{
    load_campaign_hexads, load_crosslang_hexads, load_finding_hexads, CampaignSemantic,
    FindingSemantic,
};
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
    /// `(crosslang :from FROM_CAT :to TO_CAT)` — match a `TO_CAT` finding
    /// reachable from a `FROM_CAT` finding via an FFI boundary.
    ///
    /// Evaluated in two modes depending on whether crosslang hexads have
    /// been persisted (see the module-level doc for the full semantics):
    /// facts-backed FFI-endpoint reachability when
    /// `<dir>/hexads/crosslang/` is populated, same-repo co-occurrence
    /// proxy otherwise.
    Crosslang { from: String, to: String },
    /// Match by ISO-8601 / RFC-3339 first-seen timestamp ≥ `since`.
    /// Filed under the `(since ...)` keyword for compactness; combined
    /// with `(and (category ...) (since ...))` gives the "what's new
    /// since DATE" diff query the issue calls out.
    Since(String),
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
            finish_unary_with_kwargs(category_or_rule_id(v), tokens, cursor)
        }
        "rule-id" | "ruleid" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::RuleId(v), tokens, cursor)
        }
        "severity" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::Severity(v), tokens, cursor)
        }
        "repo" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::Repo(v), tokens, cursor)
        }
        "file" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::File(v), tokens, cursor)
        }
        "pr-state" | "prstate" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::PrState(pr_state_value(v)), tokens, cursor)
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
        "since" => {
            let v = parse_value(tokens, cursor)?;
            finish_unary_with_kwargs(Query::Since(v), tokens, cursor)
        }
        "diff" => {
            // `(diff :kw VALUE ...)` — sugar for `(and (kw VALUE) ...)`.
            // Keyword-only; no positional. Matches the issue #33 example
            // `(diff :since 2026-04-12 :category PA022)` verbatim.
            let kwargs = parse_trailing_kwargs(tokens, cursor)?;
            if kwargs.is_empty() {
                bail!("(diff ...) requires at least one ':keyword VALUE' pair");
            }
            if kwargs.len() == 1 {
                Ok(kwargs.into_iter().next().unwrap())
            } else {
                Ok(Query::And(kwargs))
            }
        }
        "crosslang" => {
            // Two accepted shapes:
            //   (crosslang FROM TO)           — positional
            //   (crosslang :from FROM :to TO) — keyword
            // First token decides which.
            let mut from: Option<String> = None;
            let mut to: Option<String> = None;
            loop {
                match tokens.get(*cursor) {
                    Some(Token::RParen) => {
                        *cursor += 1;
                        break;
                    }
                    Some(Token::Atom(a)) if a.starts_with(':') => {
                        let kw = a[1..].to_ascii_lowercase();
                        *cursor += 1;
                        let v = parse_value(tokens, cursor)?;
                        match kw.as_str() {
                            "from" => from = Some(v),
                            "to" => to = Some(v),
                            other => bail!("unknown crosslang keyword: :{}", other),
                        }
                    }
                    Some(_) => {
                        // Positional fallback — `from` first, then `to`.
                        let v = parse_value(tokens, cursor)?;
                        if from.is_none() {
                            from = Some(v);
                        } else if to.is_none() {
                            to = Some(v);
                        } else {
                            bail!("too many positional args to crosslang");
                        }
                    }
                    None => bail!("missing ')' in crosslang"),
                }
            }
            let from = from.ok_or_else(|| anyhow!("crosslang missing :from"))?;
            let to = to.ok_or_else(|| anyhow!("crosslang missing :to"))?;
            Ok(Query::Crosslang { from, to })
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

/// `(category PA001)` should mean "rule-id PA001", since `category` matches
/// the `WeakPointCategory` Debug name and the PA-prefixed strings are rule
/// IDs (`PA001`..`PA025`). Issue #33's literal example
/// `(category PA001 :severity Critical :pr-state nil)` relies on this
/// routing — without it the head matches zero findings.
fn category_or_rule_id(v: String) -> Query {
    let bytes = v.as_bytes();
    let looks_like_rule_id = bytes.len() > 2
        && bytes[0].eq_ignore_ascii_case(&b'P')
        && bytes[1].eq_ignore_ascii_case(&b'A')
        && bytes[2..].iter().all(|b| b.is_ascii_digit());
    if looks_like_rule_id {
        Query::RuleId(v)
    } else {
        Query::Category(v)
    }
}

/// Translate the surface `pr-state` value into the `Option<String>` used
/// by `Query::PrState`. `nil` / `none` (case-insensitive) → `None`.
fn pr_state_value(v: String) -> Option<String> {
    if v.eq_ignore_ascii_case("nil") || v.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(v)
    }
}

/// Dispatch a `:keyword VALUE` pair to the corresponding atomic Query.
///
/// Used by both `parse_trailing_kwargs` (after a positional head value) and
/// `diff` (keyword-only). Keeps the inline-kwargs surface in lock-step with
/// the corresponding unary heads — adding a new unary head requires a row
/// here so it can also be used as an inline-kwarg or `diff` keyword.
fn query_for_keyword(kw: &str, v: String) -> Result<Query> {
    match kw {
        "category" => Ok(category_or_rule_id(v)),
        "rule-id" | "ruleid" => Ok(Query::RuleId(v)),
        "severity" => Ok(Query::Severity(v)),
        "repo" => Ok(Query::Repo(v)),
        "file" => Ok(Query::File(v)),
        "pr-state" | "prstate" => Ok(Query::PrState(pr_state_value(v))),
        "since" => Ok(Query::Since(v)),
        other => Err(anyhow!("unknown query keyword: :{}", other)),
    }
}

/// Consume an optional sequence of `:keyword VALUE` pairs followed by the
/// closing `)`. Returns each pair as a sub-`Query`.
fn parse_trailing_kwargs(tokens: &[Token], cursor: &mut usize) -> Result<Vec<Query>> {
    let mut out = Vec::new();
    loop {
        match tokens.get(*cursor) {
            Some(Token::RParen) => {
                *cursor += 1;
                return Ok(out);
            }
            Some(Token::Atom(a)) if a.starts_with(':') => {
                let kw = a[1..].to_ascii_lowercase();
                *cursor += 1;
                let v = parse_value(tokens, cursor)?;
                out.push(query_for_keyword(&kw, v)?);
            }
            Some(other) => bail!("expected ':keyword VALUE' or ')', got {:?}", other),
            None => bail!("missing ')'"),
        }
    }
}

/// After a unary head's positional value has been parsed, attach any
/// trailing `:keyword VALUE` pairs by wrapping the positional clause and
/// the keyword clauses into an `(and ...)`. If there are no kwargs, the
/// positional clause is returned as-is.
fn finish_unary_with_kwargs(
    positional: Query,
    tokens: &[Token],
    cursor: &mut usize,
) -> Result<Query> {
    let extras = parse_trailing_kwargs(tokens, cursor)?;
    if extras.is_empty() {
        Ok(positional)
    } else {
        let mut all = Vec::with_capacity(1 + extras.len());
        all.push(positional);
        all.extend(extras);
        Ok(Query::And(all))
    }
}

// ===========================================================================
// Evaluation
// ===========================================================================

/// Snapshot of one finding pre-joined with its campaign state.
struct FindingRow {
    finding: FindingSemantic,
    campaign: Option<CampaignSemantic>,
    /// `created_at` of the finding hexad — used by `(since ...)`.
    created_at: String,
}

/// Index from repo name → set of category Debug-names present in that
/// repo. Used by the co-occurrence proxy path of `(crosslang ...)`.
type RepoCategoryIndex = HashMap<String, HashSet<String>>;

/// Index from `(repo_name_lower, category_lower)` → set of files in that
/// repo that carry a finding of that category. Used by the facts-backed
/// `(crosslang ...)` path so we can check whether a candidate
/// `from`-category finding's file is an endpoint of any persisted
/// `CrossLangInteraction` in the same repo.
type RepoCategoryFileIndex = HashMap<(String, String), HashSet<String>>;

/// Index from repo name (lowercased) → list of `(source_file,
/// target_file)` pairs derived from persisted crosslang hexads. Used by
/// the facts-backed `(crosslang ...)` path.
type RepoInteractionIndex = HashMap<String, Vec<(String, String)>>;

struct EvalContext {
    rows: Vec<FindingRow>,
    repo_categories: RepoCategoryIndex,
    /// Per-repo, per-category file index. Populated unconditionally; only
    /// consulted by the facts-backed crosslang path.
    repo_category_files: RepoCategoryFileIndex,
    /// Per-repo crosslang interaction endpoints. `None` when
    /// `<dir>/hexads/crosslang/` is empty (signal to the evaluator that
    /// it should fall back to the co-occurrence proxy).
    crosslang_interactions: Option<RepoInteractionIndex>,
}

fn load_context(base_dir: &Path) -> Result<EvalContext> {
    let finding_hexads = load_finding_hexads(base_dir)?;
    let mut campaign_hexads = load_campaign_hexads(base_dir)?;
    campaign_hexads.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    let mut latest: HashMap<String, CampaignSemantic> = HashMap::new();
    for h in campaign_hexads {
        if let Some(c) = h.semantic.campaign {
            latest.insert(c.finding_id.clone(), c);
        }
    }

    let mut rows = Vec::new();
    let mut repo_categories: RepoCategoryIndex = HashMap::new();
    let mut repo_category_files: RepoCategoryFileIndex = HashMap::new();
    for h in finding_hexads {
        let created_at = h.created_at.clone();
        if let Some(f) = h.semantic.finding {
            let repo_lower = f.repo_name.to_ascii_lowercase();
            let cat_lower = f.category.to_ascii_lowercase();
            repo_categories
                .entry(repo_lower.clone())
                .or_default()
                .insert(cat_lower.clone());
            repo_category_files
                .entry((repo_lower, cat_lower))
                .or_default()
                .insert(f.file.clone());
            let campaign = latest.get(&f.finding_id).cloned();
            rows.push(FindingRow {
                finding: f,
                campaign,
                created_at,
            });
        }
    }

    // Crosslang facts: load hexads; treat empty dir as "fall back to
    // co-occurrence proxy" by leaving `crosslang_interactions = None`.
    let crosslang_hexads = load_crosslang_hexads(base_dir)?;
    let crosslang_interactions = if crosslang_hexads.is_empty() {
        None
    } else {
        let mut idx: RepoInteractionIndex = HashMap::new();
        for h in crosslang_hexads {
            let Some(cl) = h.semantic.crosslang else {
                continue;
            };
            idx.entry(cl.repo_name.to_ascii_lowercase())
                .or_default()
                .push((cl.source_file.clone(), cl.target_file.clone()));
        }
        Some(idx)
    };

    Ok(EvalContext {
        rows,
        repo_categories,
        repo_category_files,
        crosslang_interactions,
    })
}

/// Facts-backed `(crosslang :from F :to T)` check for one candidate row.
///
/// Pre-condition: `row.finding.category` already matches `to`. Returns
/// `true` when a persisted `CrossLangInteraction` in the same repo has
/// one endpoint equal to a file carrying an `F`-category finding.
fn crosslang_facts_match(row: &FindingRow, from: &str, ctx: &EvalContext) -> bool {
    let Some(by_repo) = ctx.crosslang_interactions.as_ref() else {
        return false;
    };
    let repo_lower = row.finding.repo_name.to_ascii_lowercase();
    let from_lower = from.to_ascii_lowercase();
    let Some(pairs) = by_repo.get(&repo_lower) else {
        return false;
    };
    let Some(from_files) = ctx.repo_category_files.get(&(repo_lower, from_lower)) else {
        return false;
    };
    pairs
        .iter()
        .any(|(src, tgt)| from_files.contains(src) || from_files.contains(tgt))
}

fn matches(query: &Query, row: &FindingRow, ctx: &EvalContext) -> bool {
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
        Query::Since(since) => {
            // ISO-8601 / RFC-3339 timestamps sort lexicographically when
            // the format is well-formed. Falls back to `>=` string compare
            // against either the finding hexad's created_at or the
            // first_seen_run if it parses as a timestamp.
            let candidate = if !row.finding.first_seen_run.is_empty()
                && row.finding.first_seen_run.contains('T')
            {
                row.finding.first_seen_run.as_str()
            } else {
                row.created_at.as_str()
            };
            candidate >= since.as_str()
        }
        Query::Crosslang { from, to } => {
            // The current finding must be the `to` side (so callers can
            // wrap with `and`/`or`).
            if !row.finding.category.eq_ignore_ascii_case(to) {
                return false;
            }
            // Mode 1 — facts-backed: `<dir>/hexads/crosslang/` has hexads.
            // Match when there is a persisted `CrossLangInteraction` in
            // the same repo whose source or target file is the location of
            // an `F`-category finding. This is true FFI reachability.
            if ctx.crosslang_interactions.is_some() {
                return crosslang_facts_match(row, from, ctx);
            }
            // Mode 2 — co-occurrence proxy fallback (no crosslang hexads
            // on disk yet): same-repo co-occurrence of categories.
            // Preserves S3b semantics for users who haven't enabled
            // `PANIC_ATTACK_STORE_CROSSLANG_HEXADS`.
            let from_lower = from.to_ascii_lowercase();
            ctx.repo_categories
                .get(&row.finding.repo_name.to_ascii_lowercase())
                .map(|cats| cats.contains(&from_lower))
                .unwrap_or(false)
        }
        Query::And(children) => children.iter().all(|c| matches(c, row, ctx)),
        Query::Or(children) => children.iter().any(|c| matches(c, row, ctx)),
        Query::Not(inner) => !matches(inner, row, ctx),
    }
}

/// Execute a query against the persisted hexad store and return all
/// matching findings.
pub fn run(query: &Query, base_dir: &Path) -> Result<Vec<FindingHit>> {
    let ctx = load_context(base_dir)?;
    let mut hits = Vec::new();
    for row in &ctx.rows {
        if matches(query, row, &ctx) {
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
    fn parse_since_atom() {
        let q = parse("(since 2026-04-12)").unwrap();
        assert_eq!(q, Query::Since("2026-04-12".to_string()));
    }

    #[test]
    fn parse_since_quoted() {
        let q = parse("(since \"2026-04-12T00:00:00Z\")").unwrap();
        assert_eq!(q, Query::Since("2026-04-12T00:00:00Z".to_string()));
    }

    #[test]
    fn parse_crosslang_keyword_form() {
        let q = parse("(crosslang :from UnsafeFFI :to ProofDrift)").unwrap();
        assert_eq!(
            q,
            Query::Crosslang {
                from: "UnsafeFFI".to_string(),
                to: "ProofDrift".to_string(),
            }
        );
    }

    #[test]
    fn parse_crosslang_positional_form() {
        let q = parse("(crosslang UnsafeFFI ProofDrift)").unwrap();
        assert_eq!(
            q,
            Query::Crosslang {
                from: "UnsafeFFI".to_string(),
                to: "ProofDrift".to_string(),
            }
        );
    }

    #[test]
    fn parse_crosslang_missing_keyword_errors() {
        assert!(parse("(crosslang :from UnsafeFFI)").is_err());
        assert!(parse("(crosslang :to ProofDrift)").is_err());
    }

    #[test]
    fn parse_crosslang_unknown_keyword_errors() {
        assert!(parse("(crosslang :bogus UnsafeFFI :to ProofDrift)").is_err());
    }

    #[test]
    fn run_since_filters_old_findings() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // All test fixtures stamp first_seen_run with a hexad-id that
        // does not look like an ISO timestamp; fallback is the hexad's
        // created_at, which is "now". So (since 2099) returns nothing.
        let q_future = parse("(since 2099-01-01)").unwrap();
        assert!(run(&q_future, dir.path()).unwrap().is_empty());
        // Conversely (since 2000) returns everything.
        let q_past = parse("(since 2000-01-01)").unwrap();
        assert_eq!(run(&q_past, dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn run_crosslang_matches_co_occurrence() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // Test fixture: repo "alpha" has UnsafeCode + CryptoMisuse.
        // (crosslang :from UnsafeCode :to CryptoMisuse) should match
        // the CryptoMisuse finding in alpha.
        let q = parse("(crosslang :from UnsafeCode :to CryptoMisuse)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].repo_name, "alpha");
        assert_eq!(hits[0].category, "CryptoMisuse");
    }

    #[test]
    fn run_crosslang_excludes_missing_source() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // Test fixture: no PanicPath finding anywhere. So
        // (crosslang :from PanicPath :to UnsafeCode) finds nothing.
        let q = parse("(crosslang :from PanicPath :to UnsafeCode)").unwrap();
        assert!(run(&q, dir.path()).unwrap().is_empty());
    }

    // ----- Issue #33 kanren-crosslang: facts-backed crosslang tests ---

    /// Write a synthetic crosslang hexad into
    /// `<dir>/hexads/crosslang/`. Tests use this to simulate persisted
    /// `CrossLangInteraction` facts without driving the full kanren
    /// pipeline.
    fn write_synthetic_crosslang_hexad(
        dir: &std::path::Path,
        idx: usize,
        repo: &str,
        source_file: &str,
        target_file: &str,
    ) {
        use crate::storage::{CrosslangSemantic, HexadProvenance, HexadSemantic, PanicAttackHexad};
        let h = PanicAttackHexad {
            schema: "verisimdb.hexad.v1".to_string(),
            id: format!("pa-crosslang-test-{}", idx),
            created_at: "2026-05-26T00:00:00Z".to_string(),
            provenance: HexadProvenance {
                tool: "panic-attack".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                program_path: format!("/tmp/{}", repo),
                language: "Rust".to_string(),
                attestation_hash: None,
            },
            semantic: HexadSemantic {
                total_weak_points: 0,
                critical_count: 0,
                high_count: 0,
                total_crashes: 0,
                robustness_score: 0.85,
                categories: Vec::new(),
                migration: None,
                finding: None,
                campaign: None,
                crosslang: Some(CrosslangSemantic {
                    interaction_id: format!(
                        "crosslang:{}:{}:Rust:{}:Unknown:CFfi",
                        repo, source_file, target_file
                    ),
                    source_lang: "Rust".to_string(),
                    target_lang: "Unknown".to_string(),
                    mechanism: "CFfi".to_string(),
                    source_file: source_file.to_string(),
                    source_line: None,
                    target_file: target_file.to_string(),
                    target_line: None,
                    repo_name: repo.to_string(),
                }),
            },
            document: serde_json::Value::Null,
        };
        let cl_dir = dir.join("hexads").join("crosslang");
        std::fs::create_dir_all(&cl_dir).unwrap();
        std::fs::write(
            cl_dir.join(format!("h-{}.json", idx)),
            serde_json::to_string_pretty(&h).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn run_crosslang_facts_backed_matches() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // alpha has UnsafeCode finding at src/a.rs:1 and CryptoMisuse at
        // src/a.rs:7. Plant a crosslang interaction in alpha with one
        // endpoint at src/a.rs (the UnsafeCode-finding's file). The
        // CryptoMisuse finding must now match
        // `(crosslang :from UnsafeCode :to CryptoMisuse)` via the
        // facts-backed path.
        write_synthetic_crosslang_hexad(dir.path(), 0, "alpha", "src/a.rs", "foreign");
        let q = parse("(crosslang :from UnsafeCode :to CryptoMisuse)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].repo_name, "alpha");
        assert_eq!(hits[0].category, "CryptoMisuse");
    }

    #[test]
    fn run_crosslang_falls_back_to_co_occurrence_when_no_facts() {
        // No crosslang hexads written → evaluator must take the legacy
        // co-occurrence proxy path. alpha has both UnsafeCode and
        // CryptoMisuse findings so the CryptoMisuse finding matches.
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        let q = parse("(crosslang :from UnsafeCode :to CryptoMisuse)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].repo_name, "alpha");
    }

    #[test]
    fn run_crosslang_facts_backed_no_match_when_endpoint_misses() {
        // Mixed setup: crosslang hexads ARE present (so we're on the
        // facts-backed path), but no interaction in alpha touches the
        // file that carries the UnsafeCode finding. The CryptoMisuse
        // finding must NOT match — facts-backed mode strictly requires
        // an FFI endpoint at an `from`-finding's file. This is the
        // pruning the co-occurrence proxy can't do.
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        write_synthetic_crosslang_hexad(dir.path(), 0, "alpha", "src/unrelated.rs", "foreign");
        let q = parse("(crosslang :from UnsafeCode :to CryptoMisuse)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert!(
            hits.is_empty(),
            "facts-backed mode must reject co-occurrences without a real FFI endpoint"
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

    // -----------------------------------------------------------------------
    // Issue #33 literal examples — verbatim from the issue body.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_category_pa_id_auto_routes_to_rule_id() {
        // `(category PA001)` should mean "rule-id PA001" so the issue's
        // literal example matches findings.
        let q = parse("(category PA001)").unwrap();
        assert_eq!(q, Query::RuleId("PA001".to_string()));
    }

    #[test]
    fn parse_category_word_does_not_auto_route() {
        let q = parse("(category UnsafeCode)").unwrap();
        assert_eq!(q, Query::Category("UnsafeCode".to_string()));
    }

    #[test]
    fn parse_issue_example_category_with_inline_kwargs() {
        // Issue #33 example: `(category PA001 :severity Critical :pr-state nil)`
        let q = parse("(category PA001 :severity Critical :pr-state nil)").unwrap();
        assert_eq!(
            q,
            Query::And(vec![
                Query::RuleId("PA001".to_string()),
                Query::Severity("Critical".to_string()),
                Query::PrState(None),
            ])
        );
    }

    #[test]
    fn parse_issue_example_diff_form() {
        // Issue #33 example: `(diff :since 2026-04-12 :category PA022)`
        let q = parse("(diff :since 2026-04-12 :category PA022)").unwrap();
        assert_eq!(
            q,
            Query::And(vec![
                Query::Since("2026-04-12".to_string()),
                Query::RuleId("PA022".to_string()),
            ])
        );
    }

    #[test]
    fn parse_diff_with_single_kwarg_unwraps() {
        // `(diff :since X)` is just `(since X)` — no point wrapping a single
        // clause in `(and ...)`.
        let q = parse("(diff :since 2026-04-12)").unwrap();
        assert_eq!(q, Query::Since("2026-04-12".to_string()));
    }

    #[test]
    fn parse_diff_empty_errors() {
        let err = parse("(diff)").unwrap_err().to_string();
        assert!(
            err.contains("(diff ...) requires at least one"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_diff_rejects_unknown_keyword() {
        let err = parse("(diff :nonsense X)").unwrap_err().to_string();
        assert!(
            err.contains("unknown query keyword: :nonsense"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_diff_rejects_positional_arg() {
        // `(diff X)` — bare positional before any kwarg should fail.
        let err = parse("(diff X)").unwrap_err().to_string();
        assert!(err.contains("expected ':keyword VALUE'"), "got: {}", err);
    }

    #[test]
    fn parse_inline_kwargs_on_severity_head() {
        let q = parse("(severity Critical :pr-state nil)").unwrap();
        assert_eq!(
            q,
            Query::And(vec![
                Query::Severity("Critical".to_string()),
                Query::PrState(None),
            ])
        );
    }

    #[test]
    fn parse_inline_kwargs_on_since_head() {
        let q = parse("(since 2026-04-12 :category PA022)").unwrap();
        assert_eq!(
            q,
            Query::And(vec![
                Query::Since("2026-04-12".to_string()),
                Query::RuleId("PA022".to_string()),
            ])
        );
    }

    #[test]
    fn run_issue_example_category_with_kwargs_matches() {
        // End-to-end: write findings then run the verbatim issue example.
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // None of the synthetic findings are PA001 (UnsafeCode → PA004),
        // so the verbatim issue expression yields zero matches without
        // erroring — proves the parser path is wired in.
        let q = parse("(category PA001 :severity Critical :pr-state nil)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn run_diff_form_matches_recent_findings() {
        let dir = tempdir().unwrap();
        write_test_findings(dir.path());
        // The synthetic findings carry `first_seen_run = "test-run"` which
        // is NOT a valid timestamp, so `(since ...)` falls back to the
        // hexad's `created_at`. We use a date well before the test run so
        // every finding qualifies; then category PA004 selects the
        // UnsafeCode finding from `alpha`.
        let q = parse("(diff :since 2020-01-01 :category PA004)").unwrap();
        let hits = run(&q, dir.path()).unwrap();
        assert!(
            !hits.is_empty(),
            "diff form should find UnsafeCode/PA004 findings"
        );
        assert!(hits.iter().all(|h| h.rule_id == "PA004"));
    }
}
