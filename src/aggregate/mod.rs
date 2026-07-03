// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Aggregate — fold external prover output into an assail/assault report.
//!
//! `aggregate` takes one or more *prover output* artifacts (Agda, Idris2,
//! Coq/Rocq, Lean, Isabelle, or an SMT/SAT certificate — TSTP, Alethe,
//! DRAT/LRAT), and for each one:
//!
//!   1. **Hashes** the file with BLAKE3 for non-repudiation.
//!   2. Assigns a **friendly name** (annotation, CLI label, or filename).
//!   3. Classifies its **verdict**: `Closed` (no holes), `Holes` (contains
//!      `sorry`/`Admitted`/`believe_me`/`postulate`/…), `Refuted`
//!      (counter-model / `sat`), or `Indeterminate`.
//!   4. **Reconciles** that verdict against the findings in an existing
//!      report — marking findings as proof-`Backed`, `Corroborated`, or
//!      `Contradicted` where a proof and a finding overlap.
//!
//! ## Trust model
//!
//! panic-attack does **not** re-check the proof. Every aggregated verdict
//! is explicitly conditioned on the trustworthiness of the *named proof
//! checker*. The aggregated artifact is recorded by cryptographic hash, so
//! if the assessment is later challenged the tool can show exactly which
//! bytes it was handed: a different file will not reproduce the recorded
//! hash. In other words — "I was given this file; my job is to aggregate
//! it; here is its hash. If the hash does not match, you were shown a
//! different file."
//!
//! ## Coverage annotations
//!
//! A proof artifact can declare what it covers with in-file annotations
//! (any comment syntax works — the scanner is comment-agnostic):
//!
//! ```text
//! -- @name "UnsafeCode soundness (Idris2)"
//! -- @covers sound:category:UnsafeCode
//! ```
//!
//! `@covers` takes `[claim:]kind:value` where `claim ∈ {safe, sound}`,
//! `kind ∈ {category, rule-id, file, free}`. `sound` means "the detector
//! is proven sound" (supports findings); `safe` means "the code is proven
//! safe" (contradicts a finding on the same subject). CLI `--label` and
//! `--covers` override the in-file annotations.

use crate::types::{AssailReport, WeakPointCategory};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Ingest a `proven-tests` JSON run report as an aggregate input kind.
pub mod proven_tests;

/// Upper bound on the text we scan for verdict / coverage classification.
/// The *hash* always covers the whole file (see [`hash_file`]); this cap
/// only bounds the in-memory text scan for markers.
const SCAN_READ_LIMIT: u64 = 16 * 1024 * 1024;

fn aggregate_schema_version() -> String {
    "0.1.0".to_string()
}

/// A recorded content hash. `algorithm` is carried explicitly so the
/// schema can admit additional digests later without ambiguity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashRecord {
    pub algorithm: String,
    pub hex: String,
}

/// Hash an entire file with BLAKE3 (mmap-backed) and report its size.
///
/// Unlike the bounded text scan, this reads the *whole* file so the digest
/// is a faithful fingerprint of the exact bytes aggregated.
pub fn hash_file(path: &Path) -> Result<(HashRecord, u64)> {
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_mmap(path)
        .with_context(|| format!("hashing {}", path.display()))?;
    let hex = hasher.finalize().to_hex().to_string();
    let bytes = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    Ok((
        HashRecord {
            algorithm: "blake3".to_string(),
            hex,
        },
        bytes,
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Prover {
    Agda,
    Idris2,
    Coq,
    Lean,
    Isabelle,
    Tstp,
    Alethe,
    Drat,
    Unknown,
}

impl Prover {
    fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "agda" | "agdai" => Prover::Agda,
            "idr" | "lidr" => Prover::Idris2,
            "v" => Prover::Coq,
            "lean" => Prover::Lean,
            "thy" => Prover::Isabelle,
            "tstp" | "p" | "tptp" => Prover::Tstp,
            "alethe" => Prover::Alethe,
            "drat" | "lrat" => Prover::Drat,
            _ => Prover::Unknown,
        }
    }

    /// Content sniff used when the extension is uninformative.
    fn sniff(text: &str) -> Self {
        if text.contains("believe_me") || text.contains("%default total") {
            Prover::Idris2
        } else if text.contains("Qed.") || text.contains("Admitted.") || text.contains("Proof.") {
            Prover::Coq
        } else if text.contains("postulate") || text.contains("{-# OPTIONS") {
            Prover::Agda
        } else if text.contains("theorem") && text.contains(":=") {
            Prover::Lean
        } else if text.contains("SZS status") {
            Prover::Tstp
        } else if text.contains("s UNSATISFIABLE") || text.contains("s SATISFIABLE") {
            Prover::Drat
        } else {
            Prover::Unknown
        }
    }

    /// Human label for trust statements.
    fn label(&self) -> &'static str {
        match self {
            Prover::Agda => "Agda",
            Prover::Idris2 => "Idris2",
            Prover::Coq => "Coq/Rocq",
            Prover::Lean => "Lean",
            Prover::Isabelle => "Isabelle",
            Prover::Tstp => "a TSTP-emitting prover",
            Prover::Alethe => "an Alethe-emitting SMT solver",
            Prover::Drat => "a DRAT/LRAT-emitting SAT solver",
            Prover::Unknown => "an unidentified proof checker",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProofVerdict {
    /// Fully closed: no escape hatches and a positive closure signal.
    Closed,
    /// Closed *shape* but contains holes (`sorry`/`Admitted`/`believe_me`/…).
    Holes,
    /// A refutation / counter-model (`sat` / `CounterSatisfiable`).
    Refuted,
    /// Could not be determined from the artifact.
    Indeterminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProofClaim {
    /// The artifact proves the *code is safe* (overlapping findings are
    /// therefore in tension with the proof → `Contradicted`).
    Safe,
    /// The artifact proves the *detector is sound* (overlapping findings
    /// are reinforced → `Backed`).
    Sound,
    /// No polarity declared.
    Unspecified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageKind {
    Category,
    RuleId,
    File,
    Free,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub claim: ProofClaim,
    pub kind: CoverageKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedProof {
    pub friendly_name: String,
    pub path: PathBuf,
    pub hash: HashRecord,
    pub bytes: u64,
    pub prover: Prover,
    pub verdict: ProofVerdict,
    #[serde(default)]
    pub holes: Vec<String>,
    #[serde(default)]
    pub covers: Vec<Coverage>,
    pub trust_basis: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReconcileEffect {
    /// A closed proof reinforces overlapping findings.
    Backed,
    /// A closed proof of safety conflicts with overlapping findings.
    Contradicted,
    /// A closed proof with no overlapping finding (informational).
    Corroborated,
    /// A holed / indeterminate artifact: recorded but given no weight.
    Discounted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reconciliation {
    pub proof: String,
    pub effect: ReconcileEffect,
    pub subject: String,
    pub detail: String,
    #[serde(default)]
    pub affected_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingSummary {
    pub total: usize,
    pub suppressed: usize,
    pub by_category: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateReport {
    #[serde(default = "aggregate_schema_version")]
    pub schema_version: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_report: Option<PathBuf>,
    pub aggregated_proofs: Vec<AggregatedProof>,
    pub reconciliations: Vec<Reconciliation>,
    pub finding_summary: FindingSummary,
    pub trust_disclaimer: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One proof input with optional CLI-side overrides.
#[derive(Debug, Clone)]
pub struct ProofInput {
    pub path: PathBuf,
    pub label: Option<String>,
    pub covers: Vec<Coverage>,
}

#[derive(Debug, Clone)]
pub struct AggregateConfig {
    pub proofs: Vec<ProofInput>,
    pub base_report: Option<PathBuf>,
}

const TRUST_DISCLAIMER: &str = "Aggregated verdicts rest on the trustworthiness of the named proof \
checker; panic-attack did not re-run or re-check these proofs. Each artifact is recorded by its \
BLAKE3 hash. If this assessment is later challenged, the hash identifies the exact bytes aggregated \
— a different file will not reproduce it.";

pub fn run(config: AggregateConfig) -> Result<AggregateReport> {
    if config.proofs.is_empty() {
        return Err(anyhow!("provide at least one --proof"));
    }

    let mut notes = Vec::new();

    // Load base findings (optional).
    let (findings, finding_summary, base_loaded) = match &config.base_report {
        Some(path) => match load_findings(path) {
            Ok(f) => {
                let summary = summarise(&f);
                (f, summary, true)
            }
            Err(e) => {
                notes.push(format!("base report {} not loaded: {}", path.display(), e));
                (Vec::new(), FindingSummary::default(), false)
            }
        },
        None => (Vec::new(), FindingSummary::default(), false),
    };

    let mut aggregated = Vec::new();
    let mut reconciliations = Vec::new();

    for input in &config.proofs {
        let (hash, bytes) = hash_file(&input.path)?;
        let text = read_text_bounded(&input.path)?;

        let prover = match Prover::from_path(&input.path) {
            Prover::Unknown => Prover::sniff(&text),
            p => p,
        };
        let (verdict, holes) = classify(prover, &text);

        // Coverage: CLI overrides win; otherwise scan in-file annotations.
        let mut covers = input.covers.clone();
        if covers.is_empty() {
            covers = scan_covers(&text);
        }
        // Friendly name precedence: CLI label > in-file @name > filename stem.
        let friendly_name = input
            .label
            .clone()
            .or_else(|| scan_name(&text))
            .unwrap_or_else(|| {
                input
                    .path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "proof".to_string())
            });

        let trust_basis = format!(
            "Conditioned on the soundness of {}. Recorded as {}:{} ({} bytes). Verdict: {:?}.",
            prover.label(),
            hash.algorithm,
            hash.hex,
            bytes,
            verdict
        );

        // Reconcile against findings.
        for cov in &covers {
            let matching = count_matching(&findings, cov);
            let effect = reconcile_effect(verdict, cov.claim, matching);
            let detail = reconcile_detail(prover, verdict, cov, matching);
            reconciliations.push(Reconciliation {
                proof: friendly_name.clone(),
                effect,
                subject: format!("{:?}:{}", cov.kind, cov.value),
                detail,
                affected_findings: matching,
            });
        }
        if covers.is_empty() {
            notes.push(format!(
                "{}: no coverage declared (add `@covers` annotation or --covers) — recorded but not reconciled",
                friendly_name
            ));
        }

        aggregated.push(AggregatedProof {
            friendly_name,
            path: input.path.clone(),
            hash,
            bytes,
            prover,
            verdict,
            holes,
            covers,
            trust_basis,
        });
    }

    if config.base_report.is_some() && !base_loaded {
        notes.push("reconciliation skipped: base report could not be parsed".to_string());
    }

    Ok(AggregateReport {
        schema_version: aggregate_schema_version(),
        created_at: chrono::Utc::now().to_rfc3339(),
        base_report: config.base_report,
        aggregated_proofs: aggregated,
        reconciliations,
        finding_summary,
        trust_disclaimer: TRUST_DISCLAIMER.to_string(),
        notes,
    })
}

pub fn write_report(report: &AggregateReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(report).context("serializing aggregate report")?;
    fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Hole markers per prover. Presence of any of these means the proof has
/// an escape hatch — it is not a fully closed derivation.
fn hole_markers(prover: Prover) -> &'static [&'static str] {
    match prover {
        Prover::Idris2 => &["believe_me", "assert_total", "idris_crash", "postulate"],
        Prover::Agda => &["postulate", "primTrustMe", "trustMe", "{-# NON_TERMINATING"],
        Prover::Coq => &["Admitted", "admit.", "Axiom ", "give_up"],
        Prover::Lean => &["sorry", "admit", "native_decide"],
        Prover::Isabelle => &["sorry", "oops"],
        _ => &[],
    }
}

/// Returns `(verdict, holes_found)`.
pub fn classify(prover: Prover, text: &str) -> (ProofVerdict, Vec<String>) {
    // SAT/SMT certificates: verdict is the status line, not hole markers.
    if matches!(prover, Prover::Tstp | Prover::Alethe | Prover::Drat) {
        let lower = text.to_ascii_lowercase();
        let refuted = lower.contains("s satisfiable")
            || text.contains("CounterSatisfiable")
            || text.contains("SZS status Satisfiable");
        let closed = lower.contains("s unsatisfiable")
            || text.contains("SZS status Unsatisfiable")
            || text.contains("SZS status Theorem")
            || prover == Prover::Alethe;
        let verdict = if refuted {
            ProofVerdict::Refuted
        } else if closed {
            ProofVerdict::Closed
        } else {
            ProofVerdict::Indeterminate
        };
        return (verdict, Vec::new());
    }

    // Strip comments first: prose that merely *mentions* a marker word
    // ("we avoid any postulate here") must not be mistaken for an actual
    // escape hatch. Coverage/name annotations are read from the raw text
    // elsewhere, since those deliberately live inside comments.
    let scan = strip_comments(prover, text);

    let mut holes = Vec::new();
    for marker in hole_markers(prover) {
        if scan.contains(marker) {
            holes.push(marker.trim().to_string());
        }
    }
    // Idris2/Agda metavariable holes: `?name`.
    if matches!(prover, Prover::Idris2 | Prover::Agda) && has_metavar_hole(&scan) {
        holes.push("?hole".to_string());
    }

    if !holes.is_empty() {
        return (ProofVerdict::Holes, holes);
    }

    // Positive closure signal.
    let closed = match prover {
        Prover::Coq => scan.contains("Qed.") || scan.contains("Defined."),
        _ => has_proof_keyword(&scan),
    };
    if closed {
        (ProofVerdict::Closed, holes)
    } else {
        (ProofVerdict::Indeterminate, holes)
    }
}

fn has_metavar_hole(text: &str) -> bool {
    // A `?` immediately followed by an identifier char, not part of `??`
    // or a string. Cheap scan good enough for proof sources.
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'?' {
            if let Some(&next) = bytes.get(i + 1) {
                if next.is_ascii_alphabetic() || next == b'_' {
                    return true;
                }
            }
        }
    }
    false
}

fn has_proof_keyword(text: &str) -> bool {
    const KW: &[&str] = &[
        "theorem", "lemma", "Theorem", "Lemma", "Proof", "proof", "where", ":=", "data ",
        "record ",
    ];
    KW.iter().any(|k| text.contains(k))
}

/// Remove comments before marker scanning so that prose mentioning a
/// marker word does not falsely register as a proof hole. Non-nested,
/// per-prover-family delimiters — good enough for a syntactic heuristic.
fn strip_comments(prover: Prover, text: &str) -> String {
    let mut s = text.to_string();
    // Block comments.
    let block: &[(&str, &str)] = match prover {
        Prover::Coq | Prover::Isabelle => &[("(*", "*)")],
        Prover::Idris2 | Prover::Agda => &[("{-", "-}")],
        Prover::Lean => &[("/-", "-/")],
        _ => &[],
    };
    for (open, close) in block {
        s = strip_block(&s, open, close);
    }
    // Line comments.
    let line: &[&str] = match prover {
        Prover::Idris2 | Prover::Agda | Prover::Lean | Prover::Isabelle => &["--"],
        Prover::Coq => &[],
        Prover::Tstp => &["%"],
        _ => &["--", "%", "//"],
    };
    if line.is_empty() {
        return s;
    }
    s.lines()
        .map(|l| {
            let mut cut = l.len();
            for p in line {
                if let Some(idx) = l.find(p) {
                    cut = cut.min(idx);
                }
            }
            l[..cut].to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_block(text: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(open) {
        out.push_str(&rest[..start]);
        let after = &rest[start + open.len()..];
        match after.find(close) {
            Some(end) => {
                // Preserve newlines so line numbers / structure don't collapse.
                for c in after[..end].chars() {
                    if c == '\n' {
                        out.push('\n');
                    }
                }
                rest = &after[end + close.len()..];
            }
            None => {
                // Unterminated block: drop the remainder.
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Annotation scanning
// ---------------------------------------------------------------------------

/// Extract `@name "..."` / `@name token` from the artifact text.
fn scan_name(text: &str) -> Option<String> {
    let idx = text.find("@name")?;
    let rest = text[idx + "@name".len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let token: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    }
}

/// Extract all `@covers [claim:]kind:value` annotations from the text.
fn scan_covers(text: &str) -> Vec<Coverage> {
    let mut out = Vec::new();
    let mut search = text;
    while let Some(idx) = search.find("@covers") {
        let rest = search[idx + "@covers".len()..].trim_start();
        let spec: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '"')
            .collect();
        if let Some(cov) = parse_coverage_spec(&spec) {
            out.push(cov);
        }
        search = &search[idx + "@covers".len()..];
    }
    out
}

/// Parse `[claim:]kind:value`, e.g. `sound:category:UnsafeCode`,
/// `safe:file:src/foo.rs`, `category:PanicPath`, `free:my-lemma`.
pub fn parse_coverage_spec(spec: &str) -> Option<Coverage> {
    let mut parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return None;
    }
    let claim = match parts[0] {
        "safe" => Some(ProofClaim::Safe),
        "sound" => Some(ProofClaim::Sound),
        _ => None,
    };
    if claim.is_some() {
        parts.remove(0);
        // Re-split the remainder into at most two parts (kind:value).
        if parts.len() == 1 {
            parts = parts[0].splitn(2, ':').collect();
        }
    }
    let claim = claim.unwrap_or(ProofClaim::Unspecified);
    let (kind, value) = match parts.as_slice() {
        [k, v] => (kind_of(k)?, (*v).to_string()),
        [single] => (CoverageKind::Free, (*single).to_string()),
        _ => return None,
    };
    Some(Coverage {
        claim,
        kind,
        value,
    })
}

fn kind_of(s: &str) -> Option<CoverageKind> {
    match s {
        "category" | "cat" => Some(CoverageKind::Category),
        "rule-id" | "rule" | "ruleid" => Some(CoverageKind::RuleId),
        "file" => Some(CoverageKind::File),
        "free" => Some(CoverageKind::Free),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FindingLite {
    category: WeakPointCategory,
    file: Option<String>,
}

fn load_findings(path: &Path) -> Result<Vec<FindingLite>> {
    // Try the structured assault report first (embeds an assail report).
    if let Ok(assault) = crate::report::load_report(path) {
        return Ok(from_assail(&assault.assail_report));
    }
    // Fall back to a bare assail report.
    let text = read_text_bounded(path)?;
    if let Ok(assail) = serde_json::from_str::<AssailReport>(&text) {
        return Ok(from_assail(&assail));
    }
    Err(anyhow!(
        "could not parse {} as an assault or assail report",
        path.display()
    ))
}

fn from_assail(report: &AssailReport) -> Vec<FindingLite> {
    report
        .weak_points
        .iter()
        .filter(|wp| !wp.suppressed)
        .map(|wp| FindingLite {
            category: wp.category,
            file: wp.file.clone().or_else(|| wp.location.clone()),
        })
        .collect()
}

fn summarise(findings: &[FindingLite]) -> FindingSummary {
    let mut by: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in findings {
        *by.entry(category_name(&f.category)).or_insert(0) += 1;
    }
    FindingSummary {
        total: findings.len(),
        suppressed: 0,
        by_category: by.into_iter().collect(),
    }
}

fn count_matching(findings: &[FindingLite], cov: &Coverage) -> usize {
    findings
        .iter()
        .filter(|f| matches_coverage(f, cov))
        .count()
}

fn matches_coverage(f: &FindingLite, cov: &Coverage) -> bool {
    match cov.kind {
        CoverageKind::Category => eq_loose(&category_name(&f.category), &cov.value),
        CoverageKind::RuleId => category_code(&f.category)
            .map(|c| eq_loose(c, &cov.value))
            .unwrap_or(false),
        CoverageKind::File => f
            .file
            .as_deref()
            .map(|file| {
                let file = file.split(':').next().unwrap_or(file);
                file == cov.value || file.ends_with(&cov.value) || file.contains(&cov.value)
            })
            .unwrap_or(false),
        CoverageKind::Free => false,
    }
}

/// Loose identifier comparison: case-insensitive, ignoring non-alphanumerics
/// (so `UnsafeCode`, `unsafe_code`, and `unsafe-code` all match).
fn eq_loose(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect::<String>()
    };
    norm(a) == norm(b)
}

fn reconcile_effect(verdict: ProofVerdict, claim: ProofClaim, matching: usize) -> ReconcileEffect {
    match verdict {
        ProofVerdict::Holes | ProofVerdict::Indeterminate => ReconcileEffect::Discounted,
        ProofVerdict::Closed => match claim {
            ProofClaim::Sound => ReconcileEffect::Backed,
            ProofClaim::Safe => {
                if matching > 0 {
                    ReconcileEffect::Contradicted
                } else {
                    ReconcileEffect::Corroborated
                }
            }
            ProofClaim::Unspecified => {
                if matching > 0 {
                    ReconcileEffect::Backed
                } else {
                    ReconcileEffect::Corroborated
                }
            }
        },
        ProofVerdict::Refuted => match claim {
            // A refutation of a safety claim corroborates the finding.
            ProofClaim::Safe => ReconcileEffect::Backed,
            // A refutation of a soundness claim undercuts the detector.
            ProofClaim::Sound => ReconcileEffect::Contradicted,
            ProofClaim::Unspecified => ReconcileEffect::Corroborated,
        },
    }
}

fn reconcile_detail(
    prover: Prover,
    verdict: ProofVerdict,
    cov: &Coverage,
    matching: usize,
) -> String {
    match verdict {
        ProofVerdict::Holes => format!(
            "{} artifact contains escape hatches; given no evidentiary weight against {} finding(s)",
            prover.label(),
            matching
        ),
        ProofVerdict::Indeterminate => {
            format!("{} verdict indeterminate; recorded only", prover.label())
        }
        ProofVerdict::Closed => match cov.claim {
            ProofClaim::Sound => format!(
                "closed {} proof of detector soundness backs {} overlapping finding(s)",
                prover.label(),
                matching
            ),
            ProofClaim::Safe if matching > 0 => format!(
                "closed {} safety proof CONTRADICTS {} overlapping finding(s) — review for false positive",
                prover.label(),
                matching
            ),
            _ => format!(
                "closed {} proof corroborates the assessment ({} overlap)",
                prover.label(),
                matching
            ),
        },
        ProofVerdict::Refuted => format!(
            "{} produced a refutation/counter-model touching {} finding(s)",
            prover.label(),
            matching
        ),
    }
}

fn category_name(c: &WeakPointCategory) -> String {
    format!("{:?}", c)
}

/// Map a category to its documented PA rule-id where one is assigned.
fn category_code(c: &WeakPointCategory) -> Option<&'static str> {
    use WeakPointCategory::*;
    Some(match c {
        UnsafeCode => "PA001",
        PanicPath => "PA006",
        CommandInjection => "PA011",
        UnsafeDeserialization => "PA012",
        DynamicCodeExecution => "PA013",
        UnsafeFFI => "PA014",
        AtomExhaustion => "PA015",
        PathTraversal => "PA017",
        HardcodedSecret => "PA018",
        ProofDrift => "PA021",
        CryptoMisuse => "PA022",
        SupplyChain => "PA023",
        InputBoundary => "PA024",
        MutationGap => "PA025",
        _ => return None,
    })
}

fn read_text_bounded(path: &Path) -> Result<String> {
    let mut buf = String::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(SCAN_READ_LIMIT)
        .read_to_string(&mut buf)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        let p = dir.path().join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn hashing_is_stable_and_full_file() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "a.txt", "hello proof");
        let (h1, n1) = hash_file(&p).unwrap();
        let (h2, n2) = hash_file(&p).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(n1, n2);
        assert_eq!(h1.algorithm, "blake3");
        assert_eq!(n1, "hello proof".len() as u64);
    }

    #[test]
    fn idris2_believe_me_is_holes() {
        let (v, holes) = classify(Prover::Idris2, "lemma : x = x\nlemma = believe_me ()");
        assert_eq!(v, ProofVerdict::Holes);
        assert!(holes.iter().any(|h| h == "believe_me"));
    }

    #[test]
    fn coq_qed_is_closed() {
        let (v, holes) = classify(Prover::Coq, "Theorem t : True.\nProof. exact I. Qed.");
        assert_eq!(v, ProofVerdict::Closed);
        assert!(holes.is_empty());
    }

    #[test]
    fn coq_admitted_is_holes() {
        let (v, _) = classify(Prover::Coq, "Theorem t : True.\nProof. Admitted.");
        assert_eq!(v, ProofVerdict::Holes);
    }

    #[test]
    fn comment_postulate_not_flagged_as_hole() {
        // Idris2 prose mentioning "postulate" in a line comment must not
        // count as an escape hatch.
        let (v, holes) = classify(
            Prover::Idris2,
            "-- we deliberately avoid any postulate here\ntheorem t : Nat\nt = 0\n",
        );
        assert!(holes.is_empty(), "comment word should not register: {:?}", holes);
        assert_eq!(v, ProofVerdict::Closed);
    }

    #[test]
    fn block_comment_marker_stripped() {
        // Coq block comment mentioning Admitted must not flip the verdict.
        let (v, _) = classify(
            Prover::Coq,
            "(* not Admitted, honest *)\nTheorem t : True.\nProof. exact I. Qed.\n",
        );
        assert_eq!(v, ProofVerdict::Closed);
    }

    #[test]
    fn drat_unsat_is_closed() {
        let (v, _) = classify(Prover::Drat, "s UNSATISFIABLE\n0\n");
        assert_eq!(v, ProofVerdict::Closed);
    }

    #[test]
    fn tstp_countersat_is_refuted() {
        let (v, _) = classify(Prover::Tstp, "% SZS status CounterSatisfiable");
        assert_eq!(v, ProofVerdict::Refuted);
    }

    #[test]
    fn parse_spec_variants() {
        let c = parse_coverage_spec("sound:category:UnsafeCode").unwrap();
        assert_eq!(c.claim, ProofClaim::Sound);
        assert_eq!(c.kind, CoverageKind::Category);
        assert_eq!(c.value, "UnsafeCode");

        let c = parse_coverage_spec("safe:file:src/foo.rs").unwrap();
        assert_eq!(c.claim, ProofClaim::Safe);
        assert_eq!(c.kind, CoverageKind::File);
        assert_eq!(c.value, "src/foo.rs");

        let c = parse_coverage_spec("category:PanicPath").unwrap();
        assert_eq!(c.claim, ProofClaim::Unspecified);
        assert_eq!(c.kind, CoverageKind::Category);

        let c = parse_coverage_spec("my-free-lemma").unwrap();
        assert_eq!(c.kind, CoverageKind::Free);
    }

    #[test]
    fn scan_annotations() {
        let body = "-- @name \"Strip idempotence\"\n-- @covers sound:category:ProofDrift\n";
        assert_eq!(scan_name(body).as_deref(), Some("Strip idempotence"));
        let covers = scan_covers(body);
        assert_eq!(covers.len(), 1);
        assert_eq!(covers[0].kind, CoverageKind::Category);
    }

    #[test]
    fn aggregate_reconciles_contradiction() {
        let dir = TempDir::new().unwrap();
        // A bare assail report with one UnsafeCode finding on src/foo.rs.
        let assail = serde_json::json!({
            "schema_version": "2.5",
            "program_path": "src",
            "language": "rust",
            "frameworks": [],
            "weak_points": [{
                "category": "UnsafeCode",
                "location": "src/foo.rs:10",
                "file": "src/foo.rs",
                "line": 10,
                "severity": "High",
                "description": "unsafe block",
                "recommended_attack": []
            }],
            "statistics": {
                "total_files": 1, "total_lines": 10, "languages": {},
                "unsafe_blocks": 1, "panic_sites": 0, "unwrap_calls": 0,
                "allocation_sites": 0, "io_operations": 0, "threading_constructs": 0
            },
            "file_statistics": [],
            "recommended_attacks": []
        });
        let base = dir.path().join("assail.json");
        fs::write(&base, serde_json::to_string(&assail).unwrap()).unwrap();

        // A closed Coq proof claiming src/foo.rs is SAFE.
        let proof = write(
            &dir,
            "foo_safe.v",
            "(* @covers safe:file:src/foo.rs *)\nTheorem safe : True.\nProof. exact I. Qed.\n",
        );

        let report = run(AggregateConfig {
            proofs: vec![ProofInput {
                path: proof,
                label: Some("foo safety".to_string()),
                covers: Vec::new(),
            }],
            base_report: Some(base),
        })
        .unwrap();

        assert_eq!(report.aggregated_proofs.len(), 1);
        assert_eq!(report.aggregated_proofs[0].verdict, ProofVerdict::Closed);
        assert_eq!(report.aggregated_proofs[0].hash.algorithm, "blake3");
        assert_eq!(report.reconciliations.len(), 1);
        assert_eq!(
            report.reconciliations[0].effect,
            ReconcileEffect::Contradicted
        );
        assert_eq!(report.reconciliations[0].affected_findings, 1);
    }
}
