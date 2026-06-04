// SPDX-License-Identifier: MPL-2.0

//! Persistent storage helpers for assault reports
//!
//! Two storage modes:
//! - **Filesystem**: Writes reports to timestamped files in a local directory.
//!   Supports multiple output formats (JSON, YAML, Nickel, SARIF).
//! - **VerisimDb**: Wraps reports in VerisimDB hexad format. When the `http`
//!   feature is enabled and `VERISIMDB_URL` is set, pushes to `POST /octads`
//!   on a verisim-api instance. Falls back to local filesystem otherwise.
//!
//! Both modes create parent directories as needed and return the paths of
//! all files written.

use crate::report::ReportOutputFormat;
use crate::types::AssaultReport;
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// Direct filesystem persistence in the chosen output format(s)
    Filesystem,
    /// VerisimDB hexad format (file-based; HTTP API planned)
    VerisimDb,
}

impl std::str::FromStr for StorageMode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "filesystem" | "disk" | "local" => Ok(StorageMode::Filesystem),
            "verisimdb" | "verisim" | "veri" => Ok(StorageMode::VerisimDb),
            _ => Err(()),
        }
    }
}

/// VerisimDB hexad wrapper for panic-attack reports.
///
/// A hexad is the VerisimDB unit of storage — six facets representing
/// different modalities of the same data. For panic-attack reports:
/// - document: the full JSON report
/// - semantic: extracted weak point categories and severities
/// - temporal: timestamp and duration metadata
/// - structural: dependency graph edges
/// - provenance: tool version and scan parameters
/// - identity: BLAKE3 hash of the report content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanicAttackHexad {
    /// Hexad schema version
    pub schema: String,
    /// Unique identifier for this hexad
    pub id: String,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// Tool and version that produced this report
    pub provenance: HexadProvenance,
    /// Semantic summary of findings
    pub semantic: HexadSemantic,
    /// Full report payload (JSON-encoded AssaultReport)
    pub document: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexadProvenance {
    pub tool: String,
    pub version: String,
    pub program_path: String,
    pub language: String,
    /// SHA-256 chain hash from the attestation seal, if attestation was enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexadSemantic {
    pub total_weak_points: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub total_crashes: usize,
    pub robustness_score: f64,
    pub categories: Vec<String>,
    /// Migration-specific semantic data (present when target is ReScript)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationSemantic>,
    /// Finding-level semantic data (present when this hexad represents a
    /// single WeakPoint emitted by `build_finding_hexads`, issue #33 S1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingSemantic>,
    /// Campaign-state semantic data (present when this hexad is a lifecycle
    /// update — PR registration, dismissal, poll — issue #33 S2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<CampaignSemantic>,
    /// Cross-language interaction semantic data (present when this hexad
    /// is a single `CrossLangInteraction` emitted by
    /// `build_crosslang_hexads`, issue #33 kanren-crosslang follow-up).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crosslang: Option<CrosslangSemantic>,
}

/// Campaign-state facet of a hexad: tracks the lifecycle of a single
/// finding (issue #33 S2).
///
/// Append-only: each `register-pr` / `dismiss` / `poll` emits a fresh
/// hexad with the same `finding_id` subject. `status` aggregates by
/// taking the newest by `created_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSemantic {
    /// Subject — must match a `FindingSemantic.finding_id` written by S1.
    pub finding_id: String,
    /// State label. Canonical values: "open", "pr-filed", "pr-merged",
    /// "pr-closed", "dismissed". Free-form so future states can be added
    /// without a schema bump (forward-compatible by design).
    pub state: String,
    /// PR URL when `state` is `pr-*`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,
    /// Human-readable dismissal reason when `state == "dismissed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// ISO 8601 of the last PR-state poll (S2 follow-up sets this; S2
    /// initial doesn't poll).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_polled: Option<String>,
}

/// Semantic facets of a per-finding hexad (issue #33 S1).
///
/// A per-finding hexad represents one `WeakPoint` from an assemblyline scan
/// of one repository. The `finding_id` is stable across runs (same
/// repo/file/line/category → same id), so subsequent slices (S2 PR-state
/// tracking, S3 cross-repo query) can identify a finding without comparing
/// JSON blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSemantic {
    /// Stable per-finding identifier: `finding:<repo>:<file>:<line>:<category>`.
    pub finding_id: String,
    /// Repository name (basename of repo path).
    pub repo_name: String,
    /// File path, repo-relative.
    pub file: String,
    /// Line number from the original `WeakPoint`, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// `WeakPointCategory` Debug name (e.g. "UnsafeCode").
    pub category: String,
    /// Stable rule ID (e.g. "PA004"). Mirrors the SARIF rule mapping.
    pub rule_id: String,
    /// Human-readable rule slug (e.g. "unsafe-code"). Mirrors SARIF.
    pub rule_name: String,
    /// Severity label (lowercase: "critical", "high", "medium", "low").
    pub severity: String,
    /// Per-finding description from the `WeakPoint`.
    pub description: String,
    /// Run id of the *current* run (also written to `last_seen_run`).
    ///
    /// S1 sets `first_seen_run == last_seen_run`. A later slice (S2 or a
    /// query-side aggregation in S3) is responsible for back-stamping
    /// `first_seen_run` from a prior hexad with the same `finding_id`.
    pub first_seen_run: String,
    /// Run id of the run that emitted this hexad.
    pub last_seen_run: String,
    /// Framework hint, when derivable. Reserved for future enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Cross-language interaction facet of a hexad (issue #33 kanren-crosslang
/// follow-up).
///
/// One hexad per `kanren::crosslang::CrossLangInteraction` derived from a
/// repository's `AssailReport`. Lets the `(crosslang :from :to)` evaluator
/// graduate from a same-repo co-occurrence proxy to true FFI/cross-language
/// reachability against persisted kanren-derived facts.
///
/// `source_*` and `target_*` mirror the `caller_*` and `callee_*` fields of
/// `CrossLangInteraction` respectively. The renaming makes the directional
/// semantics explicit (source → target via mechanism). `interaction_id` is a
/// stable identifier so re-runs of the same interaction produce the same
/// subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrosslangSemantic {
    /// Stable identifier:
    /// `crosslang:<repo>:<source_file>:<source_lang>:<target_file>:<target_lang>:<mechanism>`.
    pub interaction_id: String,
    /// Source-side language as `Language` Debug name (e.g. "Rust").
    pub source_lang: String,
    /// Target-side language as `Language` Debug name. May be "Unknown"
    /// when the analyzer only knows the source side (foreign FFI shim).
    pub target_lang: String,
    /// Mechanism as `InteractionMechanism` Debug name (e.g. "CFfi").
    pub mechanism: String,
    /// Source file path.
    pub source_file: String,
    /// Source-side line number, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
    /// Target file path. Often "foreign" / "subprocess" /
    /// "serialized_data" when the analyzer infers a category-only boundary.
    pub target_file: String,
    /// Target-side line number, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_line: Option<u32>,
    /// Repository name (basename of repo path).
    pub repo_name: String,
}

/// Migration-specific semantic data for VeriSimDB hexads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSemantic {
    /// Detected ReScript version bracket
    pub detected_version: String,
    /// Configuration format (bsconfig.json, rescript.json, both, none)
    pub config_format: String,
    /// Number of deprecated API calls found
    pub deprecated_api_count: usize,
    /// Number of modern @rescript/core API calls found
    pub modern_api_count: usize,
    /// Migration health score (0.0 - 1.0)
    pub health_score: f64,
    /// Snapshot label (if this was a migration-snapshot run)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_label: Option<String>,
}

/// Build a VerisimDB hexad from an assault report
fn build_hexad(report: &AssaultReport) -> Result<PanicAttackHexad> {
    let now = Utc::now();
    let id = format!(
        "pa-{}-{}",
        now.format("%Y%m%d%H%M%S"),
        &uuid_from_timestamp(now.timestamp_millis())
    );

    let critical_count = report
        .assail_report
        .weak_points
        .iter()
        .filter(|wp| matches!(wp.severity, crate::types::Severity::Critical))
        .count();
    let high_count = report
        .assail_report
        .weak_points
        .iter()
        .filter(|wp| matches!(wp.severity, crate::types::Severity::High))
        .count();

    // Unique categories found
    let mut categories: Vec<String> = report
        .assail_report
        .weak_points
        .iter()
        .map(|wp| format!("{:?}", wp.category))
        .collect();
    categories.sort();
    categories.dedup();

    let document = serde_json::to_value(report)?;

    // Build migration semantic if migration_metrics are present
    let migration = report
        .assail_report
        .migration_metrics
        .as_ref()
        .map(|m| MigrationSemantic {
            detected_version: format!("{}", m.version_bracket),
            config_format: format!("{:?}", m.config_format),
            deprecated_api_count: m.deprecated_api_count,
            modern_api_count: m.modern_api_count,
            health_score: m.health_score,
            snapshot_label: None,
        });

    Ok(PanicAttackHexad {
        schema: "verisimdb.hexad.v1".to_string(),
        id,
        created_at: now.to_rfc3339(),
        provenance: HexadProvenance {
            tool: "panic-attack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            program_path: report.assail_report.program_path.display().to_string(),
            language: format!("{:?}", report.assail_report.language),
            attestation_hash: None,
        },
        semantic: HexadSemantic {
            total_weak_points: report.assail_report.weak_points.len(),
            critical_count,
            high_count,
            total_crashes: report.total_crashes,
            robustness_score: report.overall_assessment.robustness_score,
            categories,
            migration,
            finding: None,
            campaign: None,
            crosslang: None,
        },
        document,
    })
}

/// Simple deterministic pseudo-UUID from a millisecond timestamp
fn uuid_from_timestamp(millis: i64) -> String {
    format!("{:016x}", millis as u64)
}

pub fn persist_report(
    report: &AssaultReport,
    directory: Option<&Path>,
    formats: &[ReportOutputFormat],
    modes: &[StorageMode],
) -> Result<Vec<PathBuf>> {
    let mut stored = Vec::new();
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();

    if modes.contains(&StorageMode::Filesystem) {
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("reports"));
        fs::create_dir_all(&base_dir)?;
        for format in formats {
            let file_name = format!("panic-attack-{}.{}", timestamp, format.extension());
            let path = base_dir.join(&file_name);
            let content = format.serialize(report)?;
            fs::write(&path, content)?;
            stored.push(path);
        }
    }

    if modes.contains(&StorageMode::VerisimDb) {
        let hexad = build_hexad(report)?;

        // HTTP push when VERISIMDB_URL is configured; filesystem fallback otherwise.
        #[cfg(feature = "http")]
        {
            if std::env::var("VERISIMDB_URL").is_ok() {
                let base_dir = directory
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
                let mut http_paths = push_hexad_with_fallback(&hexad, &base_dir)?;
                stored.append(&mut http_paths);
            } else {
                let base_dir = directory
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
                let hexad_dir = base_dir.join("hexads");
                fs::create_dir_all(&hexad_dir)?;
                let path = hexad_dir.join(format!("{}.json", hexad.id));
                fs::write(&path, serde_json::to_string_pretty(&hexad)?)?;
                stored.push(path);
            }
        }
        #[cfg(not(feature = "http"))]
        {
            let base_dir = directory
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
            let hexad_dir = base_dir.join("hexads");
            fs::create_dir_all(&hexad_dir)?;
            let path = hexad_dir.join(format!("{}.json", hexad.id));
            fs::write(&path, serde_json::to_string_pretty(&hexad)?)?;
            stored.push(path);
        }
    }

    Ok(stored)
}

/// Build a VerisimDB hexad from an assemblyline aggregate report.
///
/// Unlike single-repo hexads which wrap an AssaultReport, assemblyline
/// hexads capture the batch scan results across many repos.
fn build_assemblyline_hexad(
    report: &crate::assemblyline::AssemblylineReport,
) -> Result<PanicAttackHexad> {
    let now = Utc::now();
    let id = format!(
        "pa-asmline-{}-{}",
        now.format("%Y%m%d%H%M%S"),
        &uuid_from_timestamp(now.timestamp_millis())
    );

    let document = serde_json::to_value(report)?;

    // Collect unique categories from all repo results
    let mut categories: Vec<String> = Vec::new();
    for result in &report.results {
        if let Some(ref rpt) = result.report {
            for wp in &rpt.weak_points {
                let cat = format!("{:?}", wp.category);
                if !categories.contains(&cat) {
                    categories.push(cat);
                }
            }
        }
    }
    categories.sort();

    Ok(PanicAttackHexad {
        schema: "verisimdb.hexad.v1".to_string(),
        id,
        created_at: now.to_rfc3339(),
        provenance: HexadProvenance {
            tool: "panic-attack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            program_path: report.directory.display().to_string(),
            language: "multi".to_string(),
            attestation_hash: None,
        },
        semantic: HexadSemantic {
            total_weak_points: report.total_weak_points,
            critical_count: report.total_critical,
            high_count: report.results.iter().map(|r| r.high_count).sum(),
            total_crashes: 0,
            robustness_score: 0.0,
            categories,
            migration: None,
            finding: None,
            campaign: None,
            crosslang: None,
        },
        document,
    })
}

/// Env var that opts a run into per-finding hexad emission (issue #33 S1).
///
/// When set to a non-empty value AND `StorageMode::VerisimDb` is configured,
/// `persist_assemblyline_report` writes one hexad per `WeakPoint` under
/// `<dir>/hexads/findings/` in addition to the existing aggregate hexad.
pub const STORE_FINDING_HEXADS_ENV: &str = "PANIC_ATTACK_STORE_FINDING_HEXADS";

/// Return `true` when per-finding hexad emission is requested via env var.
fn finding_hexads_enabled() -> bool {
    std::env::var(STORE_FINDING_HEXADS_ENV)
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// Env var that opts a run into per-cross-language-interaction hexad
/// emission (issue #33 kanren-crosslang follow-up).
///
/// When set to a non-empty value AND `StorageMode::VerisimDb` is configured,
/// `persist_assemblyline_report` writes one hexad per
/// `kanren::crosslang::CrossLangInteraction` derived from each repo under
/// `<dir>/hexads/crosslang/` in addition to the aggregate and per-finding
/// hexads. Independent of `PANIC_ATTACK_STORE_FINDING_HEXADS` so callers
/// can opt into one without the other.
pub const STORE_CROSSLANG_HEXADS_ENV: &str = "PANIC_ATTACK_STORE_CROSSLANG_HEXADS";

/// Return `true` when per-cross-language-interaction hexad emission is
/// requested via env var.
fn crosslang_hexads_enabled() -> bool {
    std::env::var(STORE_CROSSLANG_HEXADS_ENV)
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// Build the stable finding-id for a `WeakPoint`.
///
/// Pattern: `finding:<repo>:<file>:<line>:<category>` — chosen so that two
/// scans of the same repo see the same id for the same finding, which is
/// the property S2 (`campaign register-pr`) and S3 (`query`) need.
///
/// File and line components fall back to literal `"unknown"` / `"0"` when
/// the underlying `WeakPoint` lacks them, so the id is always well-formed.
fn build_finding_id(repo_name: &str, wp: &crate::types::WeakPoint) -> String {
    let file = wp
        .file
        .clone()
        .or_else(|| wp.location.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let line = wp
        .line
        .map(|n| n.to_string())
        .unwrap_or_else(|| "0".to_string());
    format!("finding:{}:{}:{}:{:?}", repo_name, file, line, wp.category)
}

/// Map `Severity` to a lowercase string label.
fn severity_label(severity: &crate::types::Severity) -> &'static str {
    match severity {
        crate::types::Severity::Critical => "critical",
        crate::types::Severity::High => "high",
        crate::types::Severity::Medium => "medium",
        crate::types::Severity::Low => "low",
    }
}

/// Build one hexad per `WeakPoint` across all repo results in an
/// assemblyline report (issue #33 S1).
///
/// Subject identity lives in `semantic.finding.finding_id`; each emitted
/// hexad's top-level `id` remains per-run-unique so two runs of the same
/// finding produce two distinct hexad files (the join key is the
/// `finding_id`, not the hexad id).
///
/// `run_id` is shared across every finding-hexad in this run and stamped
/// into both `first_seen_run` and `last_seen_run` (S1 has no prior-run
/// lookup; that's a follow-up slice's job).
pub fn build_finding_hexads(
    report: &crate::assemblyline::AssemblylineReport,
) -> Result<Vec<PanicAttackHexad>> {
    let now = Utc::now();
    let run_id = format!(
        "pa-asmline-{}-{}",
        now.format("%Y%m%d%H%M%S"),
        &uuid_from_timestamp(now.timestamp_millis())
    );

    let mut hexads = Vec::new();
    for (repo_idx, result) in report.results.iter().enumerate() {
        let Some(assail_report) = &result.report else {
            continue;
        };
        let language = format!("{:?}", assail_report.language);

        for (wp_idx, wp) in assail_report.weak_points.iter().enumerate() {
            // Skip suppressed findings — they're audit-only, not lifecycle
            // material. Keeps the hexad store aligned with fleet/CI counts.
            if wp.suppressed {
                continue;
            }

            let finding_id = build_finding_id(&result.repo_name, wp);
            let category_str = format!("{:?}", wp.category);
            let rule_id_str = crate::report::sarif::rule_id(&wp.category).to_string();
            let rule_name_str = crate::report::sarif::rule_name(&wp.category).to_string();
            let severity_str = severity_label(&wp.severity).to_string();

            // Per-hexad id: pa-finding-<run_ts>-<repo_idx>-<wp_idx>-<short>.
            // Repo/wp indices keep collision-free even within a millisecond.
            let hexad_id = format!(
                "pa-finding-{}-{}-{}-{}",
                now.format("%Y%m%d%H%M%S"),
                repo_idx,
                wp_idx,
                &uuid_from_timestamp(now.timestamp_millis()),
            );

            let document = serde_json::json!({
                "finding_id": finding_id,
                "repo_name": result.repo_name,
                "repo_path": result.repo_path.display().to_string(),
                "weak_point": wp,
            });

            hexads.push(PanicAttackHexad {
                schema: "verisimdb.hexad.v1".to_string(),
                id: hexad_id,
                created_at: now.to_rfc3339(),
                provenance: HexadProvenance {
                    tool: "panic-attack".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    program_path: result.repo_path.display().to_string(),
                    language: language.clone(),
                    attestation_hash: None,
                },
                semantic: HexadSemantic {
                    total_weak_points: 1,
                    critical_count: matches!(wp.severity, crate::types::Severity::Critical)
                        as usize,
                    high_count: matches!(wp.severity, crate::types::Severity::High) as usize,
                    total_crashes: 0,
                    robustness_score: 0.0,
                    categories: vec![category_str.clone()],
                    migration: None,
                    finding: Some(FindingSemantic {
                        finding_id: finding_id.clone(),
                        repo_name: result.repo_name.clone(),
                        file: wp
                            .file
                            .clone()
                            .or_else(|| wp.location.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        line: wp.line,
                        category: category_str,
                        rule_id: rule_id_str,
                        rule_name: rule_name_str,
                        severity: severity_str,
                        description: wp.description.clone(),
                        first_seen_run: run_id.clone(),
                        last_seen_run: run_id.clone(),
                        framework: None,
                    }),
                    campaign: None,
                    crosslang: None,
                },
                document,
            });
        }
    }

    Ok(hexads)
}

/// Write a slice of hexads under `<base_dir>/hexads/findings/` (one file
/// per hexad). Returns the paths written.
fn write_finding_hexads(hexads: &[PanicAttackHexad], base_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = base_dir.join("hexads").join("findings");
    fs::create_dir_all(&dir)?;
    let mut written = Vec::with_capacity(hexads.len());
    for hexad in hexads {
        let path = dir.join(format!("{}.json", hexad.id));
        fs::write(&path, serde_json::to_string_pretty(hexad)?)?;
        written.push(path);
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Issue #33 kanren-crosslang — per-interaction hexad emission
// ---------------------------------------------------------------------------

/// Build the stable cross-language-interaction id for one
/// `CrossLangInteraction`.
///
/// Pattern:
/// `crosslang:<repo>:<source_file>:<source_lang>:<target_file>:<target_lang>:<mechanism>`.
/// Two scans of the same repo see the same id for the same interaction,
/// which is the property the `(crosslang :from :to)` evaluator's
/// facts-backed path needs.
fn build_crosslang_id(
    repo_name: &str,
    interaction: &crate::kanren::crosslang::CrossLangInteraction,
) -> String {
    format!(
        "crosslang:{}:{}:{:?}:{}:{:?}:{:?}",
        repo_name,
        interaction.caller_file,
        interaction.caller_lang,
        interaction.callee_file,
        interaction.callee_lang,
        interaction.mechanism,
    )
}

/// Derive `CrossLangInteraction`s for one repo by running the kanren
/// pipeline (ingest report → extract crosslang facts → load rules →
/// forward-chain → query interactions) against an isolated `FactDB`.
fn derive_crosslang_interactions_for_report(
    report: &crate::types::AssailReport,
) -> Vec<crate::kanren::crosslang::CrossLangInteraction> {
    use crate::kanren::core::LogicEngine;
    use crate::kanren::crosslang::CrossLangAnalyzer;

    let mut engine = LogicEngine::new();
    engine.ingest_report(report);
    CrossLangAnalyzer::extract_facts(&mut engine.db, report);
    CrossLangAnalyzer::load_rules(&mut engine.db);
    // Forward-chain so `ffi_risk` and friends are derivable.
    engine.analyze();
    CrossLangAnalyzer::query_interactions(&engine.db)
}

/// Build one hexad per kanren-derived `CrossLangInteraction` across every
/// repo in an assemblyline report (issue #33 kanren-crosslang follow-up).
///
/// Subject identity lives in `semantic.crosslang.interaction_id`; the
/// top-level hexad `id` is per-run-unique so two runs of the same
/// interaction produce two distinct hexad files (the join key is the
/// `interaction_id`, not the hexad id). Returns an empty `Vec` when the
/// report has no AssailReport-bearing results or no derivable interactions.
pub fn build_crosslang_hexads(
    report: &crate::assemblyline::AssemblylineReport,
) -> Result<Vec<PanicAttackHexad>> {
    let now = Utc::now();
    let run_ts = now.format("%Y%m%d%H%M%S").to_string();

    let mut hexads = Vec::new();
    for (repo_idx, result) in report.results.iter().enumerate() {
        let Some(assail_report) = &result.report else {
            continue;
        };

        let interactions = derive_crosslang_interactions_for_report(assail_report);
        for (int_idx, interaction) in interactions.iter().enumerate() {
            let interaction_id = build_crosslang_id(&result.repo_name, interaction);
            let mechanism_str = format!("{:?}", interaction.mechanism);
            let source_lang_str = format!("{:?}", interaction.caller_lang);
            let target_lang_str = format!("{:?}", interaction.callee_lang);

            // Per-hexad id collision-free even within a millisecond.
            let hexad_id = format!(
                "pa-crosslang-{}-{}-{}-{}",
                run_ts,
                repo_idx,
                int_idx,
                &uuid_from_timestamp(now.timestamp_millis()),
            );

            let document = serde_json::json!({
                "interaction_id": interaction_id,
                "repo_name": result.repo_name,
                "repo_path": result.repo_path.display().to_string(),
                "caller_file": interaction.caller_file,
                "caller_lang": source_lang_str,
                "callee_file": interaction.callee_file,
                "callee_lang": target_lang_str,
                "mechanism": mechanism_str,
                "risk_score": interaction.risk_score,
            });

            hexads.push(PanicAttackHexad {
                schema: "verisimdb.hexad.v1".to_string(),
                id: hexad_id,
                created_at: now.to_rfc3339(),
                provenance: HexadProvenance {
                    tool: "panic-attack".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    program_path: result.repo_path.display().to_string(),
                    language: format!("{:?}", assail_report.language),
                    attestation_hash: None,
                },
                semantic: HexadSemantic {
                    total_weak_points: 0,
                    critical_count: 0,
                    high_count: 0,
                    total_crashes: 0,
                    robustness_score: interaction.risk_score,
                    categories: Vec::new(),
                    migration: None,
                    finding: None,
                    campaign: None,
                    crosslang: Some(CrosslangSemantic {
                        interaction_id,
                        source_lang: format!("{:?}", interaction.caller_lang),
                        target_lang: format!("{:?}", interaction.callee_lang),
                        mechanism: mechanism_str,
                        source_file: interaction.caller_file.clone(),
                        source_line: None,
                        target_file: interaction.callee_file.clone(),
                        target_line: None,
                        repo_name: result.repo_name.clone(),
                    }),
                },
                document,
            });
        }
    }

    Ok(hexads)
}

/// Write a slice of crosslang hexads under `<base_dir>/hexads/crosslang/`
/// (one file per hexad). Returns the paths written.
fn write_crosslang_hexads(hexads: &[PanicAttackHexad], base_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = base_dir.join("hexads").join("crosslang");
    fs::create_dir_all(&dir)?;
    let mut written = Vec::with_capacity(hexads.len());
    for hexad in hexads {
        let path = dir.join(format!("{}.json", hexad.id));
        fs::write(&path, serde_json::to_string_pretty(hexad)?)?;
        written.push(path);
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Issue #33 S2 — campaign-state hexad write/load helpers
// ---------------------------------------------------------------------------

/// Maximum size (in bytes) of a single hexad JSON file we'll load from
/// disk. Hexads are small documents; anything past 16 MiB is corrupted
/// or hostile.
const HEXAD_FILE_READ_LIMIT: u64 = 16 * 1024 * 1024;

/// Build a campaign-state hexad for one lifecycle event (issue #33 S2).
///
/// Append-only: each call produces a fresh hexad with a unique id. The
/// `finding_id` is carried as the semantic subject so the newest hexad
/// per finding is the current state.
pub fn build_campaign_hexad(semantic: CampaignSemantic) -> PanicAttackHexad {
    let now = Utc::now();
    let hexad_id = format!(
        "pa-campaign-{}-{}",
        now.format("%Y%m%d%H%M%S"),
        &uuid_from_timestamp(now.timestamp_millis())
    );

    PanicAttackHexad {
        schema: "verisimdb.hexad.v1".to_string(),
        id: hexad_id,
        created_at: now.to_rfc3339(),
        provenance: HexadProvenance {
            tool: "panic-attack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
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
    }
}

/// Write a single campaign-state hexad under
/// `<base_dir>/hexads/campaign/<hexad_id>.json`. Returns the path.
pub fn write_campaign_hexad(hexad: &PanicAttackHexad, base_dir: &Path) -> Result<PathBuf> {
    let dir = base_dir.join("hexads").join("campaign");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", hexad.id));
    fs::write(&path, serde_json::to_string_pretty(hexad)?)?;
    Ok(path)
}

/// Load every JSON hexad file from a directory.
///
/// Files that fail to parse are silently skipped — this is a "best
/// effort" reader used by status/query subcommands, not a validation
/// pass. Returns hexads in filesystem-order (the caller sorts as needed).
fn load_hexad_dir(dir: &Path) -> Result<Vec<PanicAttackHexad>> {
    use std::io::Read;

    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut hexads = Vec::new();
    for entry in fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let mut content = String::new();
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        if file
            .take(HEXAD_FILE_READ_LIMIT)
            .read_to_string(&mut content)
            .is_err()
        {
            continue;
        }
        if let Ok(hexad) = serde_json::from_str::<PanicAttackHexad>(&content) {
            hexads.push(hexad);
        }
    }
    Ok(hexads)
}

/// Load every per-finding hexad from `<base_dir>/hexads/findings/`.
pub fn load_finding_hexads(base_dir: &Path) -> Result<Vec<PanicAttackHexad>> {
    load_hexad_dir(&base_dir.join("hexads").join("findings"))
}

/// Load every campaign-state hexad from `<base_dir>/hexads/campaign/`.
pub fn load_campaign_hexads(base_dir: &Path) -> Result<Vec<PanicAttackHexad>> {
    load_hexad_dir(&base_dir.join("hexads").join("campaign"))
}

/// Load every cross-language-interaction hexad from
/// `<base_dir>/hexads/crosslang/`. Returns an empty `Vec` when the
/// directory doesn't exist — callers (notably the `(crosslang :from :to)`
/// query evaluator's facts-backed path) treat the empty case as "fall back
/// to co-occurrence proxy".
pub fn load_crosslang_hexads(base_dir: &Path) -> Result<Vec<PanicAttackHexad>> {
    load_hexad_dir(&base_dir.join("hexads").join("crosslang"))
}

/// Load every aggregate (per-run) hexad from `<base_dir>/hexads/`.
///
/// Aggregate hexads live at the top-level `hexads/` directory; per-finding
/// and per-campaign hexads live in subdirs and are excluded here.
///
/// Reserved for S3 query — kept public so the upcoming `query` subcommand
/// can compose it with the per-finding / per-campaign loaders.
#[allow(dead_code)]
pub fn load_aggregate_hexads(base_dir: &Path) -> Result<Vec<PanicAttackHexad>> {
    load_hexad_dir(&base_dir.join("hexads"))
}

/// Persist an assemblyline report to storage (filesystem and/or verisimdb).
///
/// This is the batch-scan counterpart to `persist_report()` — it stores
/// the aggregate assemblyline report rather than individual assault reports.
pub fn persist_assemblyline_report(
    report: &crate::assemblyline::AssemblylineReport,
    directory: Option<&Path>,
    modes: &[StorageMode],
) -> Result<Vec<PathBuf>> {
    let mut stored = Vec::new();
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();

    if modes.contains(&StorageMode::Filesystem) {
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("reports"));
        fs::create_dir_all(&base_dir)?;
        let file_name = format!("assemblyline-{}.json", timestamp);
        let path = base_dir.join(&file_name);
        let content = serde_json::to_string_pretty(report)?;
        fs::write(&path, content)?;
        stored.push(path);
    }

    if modes.contains(&StorageMode::VerisimDb) {
        let hexad = build_assemblyline_hexad(report)?;
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("verisimdb-data"));

        #[cfg(feature = "http")]
        {
            if std::env::var("VERISIMDB_URL").is_ok() {
                let mut http_paths = push_hexad_with_fallback(&hexad, &base_dir)?;
                stored.append(&mut http_paths);
            } else {
                let hexad_dir = base_dir.join("hexads");
                fs::create_dir_all(&hexad_dir)?;
                let path = hexad_dir.join(format!("{}.json", hexad.id));
                fs::write(&path, serde_json::to_string_pretty(&hexad)?)?;
                stored.push(path);
            }
        }
        #[cfg(not(feature = "http"))]
        {
            let hexad_dir = base_dir.join("hexads");
            fs::create_dir_all(&hexad_dir)?;
            let path = hexad_dir.join(format!("{}.json", hexad.id));
            fs::write(&path, serde_json::to_string_pretty(&hexad)?)?;
            stored.push(path);
        }

        // Per-finding hexads (issue #33 S1) — additive, env-var gated, and
        // always file-side for now. HTTP push for finding hexads is left
        // to S3/query path so we don't add chattiness to the API mid-S1.
        if finding_hexads_enabled() {
            let finding_hexads = build_finding_hexads(report)?;
            let mut paths = write_finding_hexads(&finding_hexads, &base_dir)?;
            stored.append(&mut paths);
        }

        // Per-cross-language-interaction hexads (issue #33 kanren-crosslang
        // follow-up). Independent env-var from the finding-hexad gate so
        // callers can opt into one without the other. File-side only for
        // the same reason — HTTP push deferred to keep the API quiet
        // until the surface stabilises.
        if crosslang_hexads_enabled() {
            let crosslang_hexads = build_crosslang_hexads(report)?;
            let mut paths = write_crosslang_hexads(&crosslang_hexads, &base_dir)?;
            stored.append(&mut paths);
        }
    }

    Ok(stored)
}

// ---------------------------------------------------------------------------
// VeriSimDB HTTP API integration (direct verisim-api, port 8080)
// ---------------------------------------------------------------------------

/// Map a `PanicAttackHexad` to the verisim-api `OctadRequest` JSON shape.
///
/// Field mapping:
/// - `title`: "panic-attack scan: {path} @ {created_at}"
/// - `body`: JSON-serialised document facet
/// - `types`: `["http://hyperpolymath.dev/panic-attack/AssailReport"]`
/// - `metadata`: semantic fields (counts, score, categories) as string values
/// - `provenance`: tool/version → actor, program_path → source
#[cfg(feature = "http")]
fn hexad_to_octad_request(hexad: &PanicAttackHexad) -> serde_json::Value {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert(
        "total_weak_points".to_string(),
        hexad.semantic.total_weak_points.to_string(),
    );
    metadata.insert(
        "critical_count".to_string(),
        hexad.semantic.critical_count.to_string(),
    );
    metadata.insert(
        "high_count".to_string(),
        hexad.semantic.high_count.to_string(),
    );
    metadata.insert(
        "robustness_score".to_string(),
        format!("{:.4}", hexad.semantic.robustness_score),
    );
    metadata.insert(
        "categories".to_string(),
        hexad.semantic.categories.join(","),
    );
    metadata.insert("tool_version".to_string(), hexad.provenance.version.clone());
    metadata.insert("language".to_string(), hexad.provenance.language.clone());

    let body = serde_json::to_string(&hexad.document).unwrap_or_default();
    let title = format!(
        "panic-attack scan: {} @ {}",
        hexad.provenance.program_path, hexad.created_at
    );
    let description = format!(
        "panic-attack {} scan of {} — {} weak points ({} critical, {} high)",
        hexad.provenance.version,
        hexad.provenance.program_path,
        hexad.semantic.total_weak_points,
        hexad.semantic.critical_count,
        hexad.semantic.high_count,
    );

    serde_json::json!({
        "title": title,
        "body": body,
        "types": ["http://hyperpolymath.dev/panic-attack/AssailReport"],
        "metadata": metadata,
        "provenance": {
            "event_type": "created",
            "actor": format!("panic-attack/{}", hexad.provenance.version),
            "source": hexad.provenance.program_path,
            "description": description,
        }
    })
}

/// Push a hexad to the verisim-api directly via REST.
///
/// Endpoint: POST http://{verisimdb_url}/octads
///
/// Requires the `http` feature flag: `cargo build --features http`
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_http(hexad: &PanicAttackHexad, gateway_url: &str) -> Result<String> {
    let url = format!("{}/octads", gateway_url.trim_end_matches('/'));
    let payload_bytes = serde_json::to_vec(&hexad_to_octad_request(hexad))?;

    let mut builder = ureq::post(&url).header("Content-Type", "application/json");
    if let Some(token) = auth_token() {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }
    let response = builder
        .send(&payload_bytes[..])
        .map_err(|e| anyhow!("VeriSimDB push error: {}", e))?;

    let status = response.status().as_u16();
    let body = read_body(response);

    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(anyhow!("VeriSimDB returned {}: {}", status, body))
    }
}

/// Push a hexad via HTTP, falling back to filesystem if the API is unavailable.
///
/// Uses VERISIMDB_URL env var (default: http://localhost:8080).
/// Checks API health (cached for 30s) before attempting HTTP push.
/// Retries with exponential backoff (3 attempts: 1s, 2s, 4s) before falling back.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_with_fallback(
    hexad: &PanicAttackHexad,
    fallback_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let gateway_url =
        std::env::var("VERISIMDB_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Skip HTTP entirely if gateway is known-down (cached health check)
    if !check_gateway(&gateway_url) {
        return fallback_write_hexad(hexad, fallback_dir);
    }

    match push_hexad_http_with_retry(hexad, &gateway_url) {
        Ok(_response) => Ok(Vec::new()), // pushed via HTTP, no local file
        Err(_) => {
            // All retries exhausted — fall back to filesystem
            fallback_write_hexad(hexad, fallback_dir)
        }
    }
}

/// Write a hexad to the local filesystem fallback directory.
#[cfg(feature = "http")]
fn fallback_write_hexad(hexad: &PanicAttackHexad, fallback_dir: &Path) -> Result<Vec<PathBuf>> {
    let hexad_dir = fallback_dir.join("hexads");
    fs::create_dir_all(&hexad_dir)?;
    let path = hexad_dir.join(format!("{}.json", hexad.id));
    let payload = serde_json::to_string_pretty(hexad)?;
    fs::write(&path, &payload)?;
    Ok(vec![path])
}

/// Persist a report to VeriSimDB via HTTP API (with filesystem fallback).
///
/// This is the HTTP-enabled counterpart to the file-based VerisimDb mode.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn persist_report_http(
    report: &AssaultReport,
    fallback_dir: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let hexad = build_hexad(report)?;
    let dir = fallback_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
    push_hexad_with_fallback(&hexad, &dir)
}

/// Persist an assemblyline report to VeriSimDB via HTTP API (with filesystem fallback).
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn persist_assemblyline_report_http(
    report: &crate::assemblyline::AssemblylineReport,
    fallback_dir: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let hexad = build_assemblyline_hexad(report)?;
    let dir = fallback_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
    push_hexad_with_fallback(&hexad, &dir)
}

// ---------------------------------------------------------------------------
// VeriSimDB HTTP API — retry, auth, batch, query, health check
// (ureq v3 API: builders, http::StatusCode, body via Read trait)
// ---------------------------------------------------------------------------

/// Cached API health state: stores (is_healthy, timestamp_secs).
/// Used to avoid repeated HTTP attempts against a known-down API.
#[cfg(feature = "http")]
static GATEWAY_HEALTH: std::sync::OnceLock<std::sync::Mutex<(bool, u64)>> =
    std::sync::OnceLock::new();

/// Duration (in seconds) to cache an API health check result.
#[cfg(feature = "http")]
const HEALTH_CACHE_TTL_SECS: u64 = 30;

/// Return the current wall-clock time in seconds since UNIX epoch.
#[cfg(feature = "http")]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Return the Bearer token from `VERISIM_API_TOKEN` env var, if set.
#[cfg(feature = "http")]
fn auth_token() -> Option<String> {
    match std::env::var("VERISIM_API_TOKEN") {
        Ok(t) if !t.is_empty() => Some(t),
        _ => None,
    }
}

/// Read an ureq v3 response body as a String.
///
/// ureq v3: `response.body_mut().read_to_string()` returns `Result<String>`.
#[cfg(feature = "http")]
fn read_body(mut response: ureq::http::Response<ureq::Body>) -> String {
    response.body_mut().read_to_string().unwrap_or_default()
}

/// Push a single hexad with exponential-backoff retry.
///
/// Makes up to 3 attempts with delays of 1 s, 2 s, 4 s between them.
/// Returns as soon as one attempt succeeds.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_http_with_retry(hexad: &PanicAttackHexad, gateway_url: &str) -> Result<String> {
    let delays = [
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(4),
    ];
    let max_attempts = delays.len();
    let mut last_err: Option<anyhow::Error> = None;

    for (attempt, delay) in delays.iter().enumerate() {
        match push_hexad_http(hexad, gateway_url) {
            Ok(body) => return Ok(body),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts - 1 {
                    std::thread::sleep(*delay);
                }
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| anyhow!("VeriSimDB push failed after {} attempts", max_attempts)))
}

/// Push a batch of hexads to the VeriSimDB batch endpoint.
///
/// Endpoint: POST `{verisimdb_url}/octads/batch`
///
/// If the batch endpoint returns HTTP 404 (not yet implemented), falls back to
/// pushing each hexad individually via [`push_hexad_http_with_retry`].
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexads_batch(hexads: &[PanicAttackHexad], gateway_url: &str) -> Result<Vec<String>> {
    if hexads.is_empty() {
        return Ok(Vec::new());
    }

    let url = format!("{}/octads/batch", gateway_url.trim_end_matches('/'));
    let payloads: Vec<serde_json::Value> = hexads.iter().map(hexad_to_octad_request).collect();
    let payload_bytes = serde_json::to_vec(&payloads)?;

    let mut builder = ureq::post(&url).header("Content-Type", "application/json");
    if let Some(token) = auth_token() {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }

    match builder.send(&payload_bytes[..]) {
        Ok(response) => {
            let status = response.status().as_u16();
            if status == 404 {
                // Batch endpoint not yet implemented — push individually
                let mut results = Vec::with_capacity(hexads.len());
                for hexad in hexads {
                    let body = push_hexad_http_with_retry(hexad, gateway_url)?;
                    results.push(body);
                }
                Ok(results)
            } else if (200..300).contains(&status) {
                Ok(vec![read_body(response)])
            } else {
                let body = read_body(response);
                Err(anyhow!("VeriSimDB batch returned {}: {}", status, body))
            }
        }
        Err(e) => Err(anyhow!("VeriSimDB batch request failed: {}", e)),
    }
}

/// Query octads from VeriSimDB for temporal diff comparison.
///
/// Endpoint: GET `{verisimdb_url}/octads?tool=panic-attack&limit={limit}`
///
/// Returns parsed hexads from the API. Useful for comparing current scan
/// results against previous scans stored in VeriSimDB.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn query_hexads(gateway_url: &str, limit: usize) -> Result<Vec<PanicAttackHexad>> {
    let url = format!(
        "{}/octads?tool=panic-attack&limit={}",
        gateway_url.trim_end_matches('/'),
        limit,
    );

    let mut builder = ureq::get(&url);
    if let Some(token) = auth_token() {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }
    let response = builder
        .call()
        .map_err(|e| anyhow!("VeriSimDB query failed: {}", e))?;

    let status = response.status().as_u16();
    let body = read_body(response);

    if (200..300).contains(&status) {
        let hexads: Vec<PanicAttackHexad> = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse VeriSimDB response: {}", e))?;
        Ok(hexads)
    } else {
        Err(anyhow!("VeriSimDB query returned {}: {}", status, body))
    }
}

/// Check whether the VeriSimDB API is reachable.
///
/// Endpoint: GET `{verisimdb_url}/health`
///
/// Results are cached for 30 seconds via a static `OnceLock<Mutex<...>>` to
/// avoid hammering a down API on every push call. Returns `true` if the API
/// responded 2xx within the cache window, `false` otherwise.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn check_gateway(gateway_url: &str) -> bool {
    let mutex = GATEWAY_HEALTH.get_or_init(|| std::sync::Mutex::new((false, 0)));
    let now = now_secs();

    // Return cached result if still fresh
    if let Ok(guard) = mutex.lock() {
        let (healthy, checked_at) = *guard;
        if now.saturating_sub(checked_at) < HEALTH_CACHE_TTL_SECS {
            return healthy;
        }
    }

    // Cache expired or first call — perform live check
    let url = format!("{}/health", gateway_url.trim_end_matches('/'));
    let mut builder = ureq::get(&url);
    if let Some(token) = auth_token() {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }
    let is_healthy = match builder.call() {
        Ok(resp) => {
            let s = resp.status().as_u16();
            (200..300).contains(&s)
        }
        Err(_) => false,
    };

    // Update cache
    if let Ok(mut guard) = mutex.lock() {
        *guard = (is_healthy, now);
    }

    is_healthy
}

pub fn latest_reports(dir: &Path, count: usize) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Err(anyhow!("storage directory not found: {}", dir.display()));
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    if entries.len() < count {
        return Err(anyhow!(
            "not enough reports in {} (need {}, found {})",
            dir.display(),
            count,
            entries.len()
        ));
    }
    let start = entries.len() - count;
    Ok(entries[start..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_uuid_from_timestamp() {
        let id = uuid_from_timestamp(1709155200000);
        assert!(!id.is_empty());
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_storage_mode_parsing() {
        assert_eq!(
            "filesystem".parse::<StorageMode>(),
            Ok(StorageMode::Filesystem)
        );
        assert_eq!(
            "verisimdb".parse::<StorageMode>(),
            Ok(StorageMode::VerisimDb)
        );
        assert_eq!("disk".parse::<StorageMode>(), Ok(StorageMode::Filesystem));
        assert_eq!("bogus".parse::<StorageMode>(), Err(()));
    }

    // ----- Issue #33 S1: per-finding hexad tests -----------------------

    use crate::assemblyline::{AssemblylineReport, RepoResult};
    use crate::types::{
        AssailReport, Language, ProgramStatistics, Severity, WeakPoint, WeakPointCategory,
    };
    use std::path::PathBuf;

    fn sample_weak_point(file: &str, line: u32, category: WeakPointCategory) -> WeakPoint {
        WeakPoint {
            category,
            location: Some(format!("{}:{}", file, line)),
            file: Some(file.to_string()),
            line: Some(line),
            severity: Severity::High,
            description: format!("test finding at {}:{}", file, line),
            recommended_attack: Vec::new(),
            suppressed: false,
                test_context: None,
        }
    }

    fn sample_assemblyline(repo: &str, wps: Vec<WeakPoint>) -> AssemblylineReport {
        let assail = AssailReport {
            schema_version: "2.5".to_string(),
            program_path: PathBuf::from(format!("/tmp/{}", repo)),
            language: Language::Rust,
            frameworks: Vec::new(),
            weak_points: wps,
            statistics: ProgramStatistics::default(),
            file_statistics: Vec::new(),
            recommended_attacks: Vec::new(),
            dependency_graph: Default::default(),
            taint_matrix: Default::default(),
            migration_metrics: None,
            suppressed_count: 0,
        };
        AssemblylineReport {
            schema_version: "2.5".to_string(),
            created_at: "2026-05-26T00:00:00Z".to_string(),
            directory: PathBuf::from("/tmp"),
            repos_scanned: 1,
            repos_with_findings: 1,
            repos_skipped: 0,
            total_weak_points: assail.weak_points.len(),
            total_critical: 0,
            results: vec![RepoResult {
                repo_path: PathBuf::from(format!("/tmp/{}", repo)),
                repo_name: repo.to_string(),
                weak_point_count: assail.weak_points.len(),
                critical_count: 0,
                high_count: assail.weak_points.len(),
                total_files: 1,
                total_lines: 10,
                error: None,
                fingerprint: None,
                report: Some(assail),
            }],
        }
    }

    // PROOF-PROGRAMME §3.1 (Hexad↔Octad), faithful form.
    //
    // The gateway projection `hexad_to_octad_request` is intentionally
    // *lossy* — it flattens the semantic facet into a string metadata map
    // and drops `id` / the optional sub-facets — so it is NOT an
    // isomorphism. The property that actually underwrites on-disk integrity
    // is the serde round-trip exercised by `write_*_hexad` → `load_hexad_dir`:
    // a hexad serialised to its canonical JSON and read back must be
    // identical. This proptest establishes that round-trip is the identity
    // on the hexad's JSON representation (compared as `serde_json::Value`,
    // so it is independent of key ordering). Equality is checked on the
    // Value rather than the struct because `PanicAttackHexad` deliberately
    // does not derive `PartialEq`.
    proptest! {
        #[test]
        fn hexad_json_roundtrip_is_identity(
            id in "[A-Za-z0-9:_./-]{0,48}",
            program in "[A-Za-z0-9:_./-]{0,48}",
            language in "[a-z]{0,12}",
            version in "[0-9.]{1,8}",
            total in 0usize..10_000,
            crit in 0usize..10_000,
            high in 0usize..10_000,
            crashes in 0usize..10_000,
            robustness in 0.0f64..=1.0,
            cats in proptest::collection::vec("[A-Za-z]{1,16}", 0..6),
            attest in proptest::option::of("[0-9a-f]{0,64}"),
        ) {
            let hexad = PanicAttackHexad {
                schema: "panic-attack-hexad/1".to_string(),
                id,
                created_at: "2026-06-04T00:00:00Z".to_string(),
                provenance: HexadProvenance {
                    tool: "panic-attack".to_string(),
                    version,
                    program_path: program,
                    language,
                    attestation_hash: attest,
                },
                semantic: HexadSemantic {
                    total_weak_points: total,
                    critical_count: crit,
                    high_count: high,
                    total_crashes: crashes,
                    robustness_score: robustness,
                    categories: cats,
                    migration: None,
                    finding: None,
                    campaign: None,
                    crosslang: None,
                },
                document: serde_json::json!({ "weak_points": [], "n": total }),
            };
            let v1 = serde_json::to_value(&hexad).expect("serialise");
            let back: PanicAttackHexad =
                serde_json::from_value(v1.clone()).expect("deserialise");
            let v2 = serde_json::to_value(&back).expect("re-serialise");
            prop_assert_eq!(v1, v2);
        }
    }

    #[test]
    fn build_finding_id_stable_per_finding() {
        let wp = sample_weak_point("src/main.rs", 42, WeakPointCategory::UnsafeCode);
        let id_1 = build_finding_id("foo", &wp);
        let id_2 = build_finding_id("foo", &wp);
        assert_eq!(id_1, id_2);
        assert_eq!(id_1, "finding:foo:src/main.rs:42:UnsafeCode");
    }

    #[test]
    fn build_finding_id_differs_by_category() {
        let wp1 = sample_weak_point("src/main.rs", 42, WeakPointCategory::UnsafeCode);
        let wp2 = sample_weak_point("src/main.rs", 42, WeakPointCategory::PanicPath);
        assert_ne!(build_finding_id("foo", &wp1), build_finding_id("foo", &wp2));
    }

    #[test]
    fn build_finding_hexads_emits_one_per_weak_point() {
        let report = sample_assemblyline(
            "demo",
            vec![
                sample_weak_point("src/a.rs", 1, WeakPointCategory::UnsafeCode),
                sample_weak_point("src/b.rs", 7, WeakPointCategory::PanicPath),
                sample_weak_point("src/c.rs", 9, WeakPointCategory::CommandInjection),
            ],
        );
        let hexads = build_finding_hexads(&report).expect("build ok");
        assert_eq!(hexads.len(), 3);
        for h in &hexads {
            let f = h
                .semantic
                .finding
                .as_ref()
                .expect("each per-finding hexad must carry FindingSemantic");
            assert!(f.finding_id.starts_with("finding:demo:"));
            assert_eq!(f.repo_name, "demo");
            assert_eq!(f.severity, "high");
            assert!(!f.rule_id.is_empty());
            assert_eq!(f.first_seen_run, f.last_seen_run);
        }
    }

    #[test]
    fn build_finding_hexads_skips_suppressed() {
        let mut suppressed = sample_weak_point("src/a.rs", 1, WeakPointCategory::UnsafeCode);
        suppressed.suppressed = true;
        let report = sample_assemblyline(
            "demo",
            vec![
                suppressed,
                sample_weak_point("src/b.rs", 2, WeakPointCategory::PanicPath),
            ],
        );
        let hexads = build_finding_hexads(&report).expect("build ok");
        assert_eq!(hexads.len(), 1);
        assert_eq!(
            hexads[0].semantic.finding.as_ref().unwrap().category,
            "PanicPath"
        );
    }

    #[test]
    fn build_finding_hexads_uses_canonical_rule_ids() {
        let report = sample_assemblyline(
            "demo",
            vec![sample_weak_point(
                "src/x.rs",
                3,
                WeakPointCategory::UnsafeCode,
            )],
        );
        let hexads = build_finding_hexads(&report).expect("build ok");
        let f = hexads[0].semantic.finding.as_ref().unwrap();
        assert_eq!(f.rule_id, "PA004");
        assert_eq!(f.rule_name, "unsafe-code");
    }

    #[test]
    fn write_finding_hexads_writes_one_file_per_hexad() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = sample_assemblyline(
            "demo",
            vec![
                sample_weak_point("src/a.rs", 1, WeakPointCategory::UnsafeCode),
                sample_weak_point("src/b.rs", 2, WeakPointCategory::PanicPath),
            ],
        );
        let hexads = build_finding_hexads(&report).expect("build ok");
        let paths = write_finding_hexads(&hexads, dir.path()).expect("write ok");
        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert!(p.exists());
            // sanity: parses back as a hexad
            let content = std::fs::read_to_string(p).unwrap();
            let parsed: PanicAttackHexad = serde_json::from_str(&content).unwrap();
            assert!(parsed.semantic.finding.is_some());
        }
    }

    #[test]
    fn finding_hexads_disabled_by_default() {
        // Snapshot+restore so we don't trample on parallel-test global state.
        let original = std::env::var(STORE_FINDING_HEXADS_ENV).ok();
        std::env::remove_var(STORE_FINDING_HEXADS_ENV);
        assert!(!finding_hexads_enabled());
        if let Some(v) = original {
            std::env::set_var(STORE_FINDING_HEXADS_ENV, v);
        }
    }

    // ----- Issue #33 kanren-crosslang: per-interaction hexad tests -----

    fn ffi_weak_point(file: &str, line: u32) -> WeakPoint {
        WeakPoint {
            category: WeakPointCategory::UnsafeFFI,
            location: Some(format!("{}:{}", file, line)),
            file: Some(file.to_string()),
            line: Some(line),
            severity: Severity::High,
            description: "ffi boundary".to_string(),
            recommended_attack: Vec::new(),
            suppressed: false,
                test_context: None,
        }
    }

    fn assemblyline_with_ffi(repo: &str) -> AssemblylineReport {
        let assail = AssailReport {
            schema_version: "2.5".to_string(),
            program_path: PathBuf::from(format!("/tmp/{}", repo)),
            language: Language::Rust,
            frameworks: Vec::new(),
            weak_points: vec![ffi_weak_point("src/bridge.rs", 42)],
            statistics: ProgramStatistics::default(),
            file_statistics: Vec::new(),
            recommended_attacks: Vec::new(),
            dependency_graph: Default::default(),
            taint_matrix: Default::default(),
            migration_metrics: None,
            suppressed_count: 0,
        };
        AssemblylineReport {
            schema_version: "2.5".to_string(),
            created_at: "2026-05-26T00:00:00Z".to_string(),
            directory: PathBuf::from("/tmp"),
            repos_scanned: 1,
            repos_with_findings: 1,
            repos_skipped: 0,
            total_weak_points: assail.weak_points.len(),
            total_critical: 0,
            results: vec![RepoResult {
                repo_path: PathBuf::from(format!("/tmp/{}", repo)),
                repo_name: repo.to_string(),
                weak_point_count: assail.weak_points.len(),
                critical_count: 0,
                high_count: assail.weak_points.len(),
                total_files: 1,
                total_lines: 10,
                error: None,
                fingerprint: None,
                report: Some(assail),
            }],
        }
    }

    #[test]
    fn build_crosslang_hexads_empty_when_no_reports() {
        let empty = AssemblylineReport {
            schema_version: "2.5".to_string(),
            created_at: "2026-05-26T00:00:00Z".to_string(),
            directory: PathBuf::from("/tmp"),
            repos_scanned: 0,
            repos_with_findings: 0,
            repos_skipped: 0,
            total_weak_points: 0,
            total_critical: 0,
            results: Vec::new(),
        };
        let hexads = build_crosslang_hexads(&empty).expect("build ok");
        assert!(hexads.is_empty());
    }

    #[test]
    fn build_crosslang_hexads_emits_from_ffi_weak_point() {
        let report = assemblyline_with_ffi("demo");
        let hexads = build_crosslang_hexads(&report).expect("build ok");
        assert!(
            !hexads.is_empty(),
            "UnsafeFFI weak point must produce ≥1 crosslang interaction hexad"
        );
        for h in &hexads {
            let cl = h
                .semantic
                .crosslang
                .as_ref()
                .expect("each crosslang hexad must carry CrosslangSemantic");
            assert_eq!(cl.repo_name, "demo");
            assert!(cl.interaction_id.starts_with("crosslang:demo:"));
            assert!(!cl.mechanism.is_empty());
            // finding/campaign facets stay empty on a crosslang hexad.
            assert!(h.semantic.finding.is_none());
            assert!(h.semantic.campaign.is_none());
        }
    }

    #[test]
    fn write_then_load_crosslang_hexads_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = assemblyline_with_ffi("demo");
        let hexads = build_crosslang_hexads(&report).expect("build ok");
        assert!(!hexads.is_empty());
        let written = write_crosslang_hexads(&hexads, dir.path()).expect("write ok");
        assert_eq!(written.len(), hexads.len());

        let loaded = load_crosslang_hexads(dir.path()).expect("load ok");
        assert_eq!(loaded.len(), hexads.len());
        for h in &loaded {
            assert!(h.semantic.crosslang.is_some());
        }
        // Missing dir → empty Vec, never error.
        let other = tempfile::tempdir().expect("tempdir2");
        let empty = load_crosslang_hexads(other.path()).expect("load ok");
        assert!(empty.is_empty());
    }

    #[test]
    fn crosslang_hexads_disabled_by_default() {
        // Mirrors `finding_hexads_disabled_by_default`. Snapshot+restore so we
        // play nicely with parallel-test global env-var state.
        let original = std::env::var(STORE_CROSSLANG_HEXADS_ENV).ok();
        std::env::remove_var(STORE_CROSSLANG_HEXADS_ENV);
        assert!(!crosslang_hexads_enabled());
        std::env::set_var(STORE_CROSSLANG_HEXADS_ENV, "1");
        assert!(crosslang_hexads_enabled());
        std::env::remove_var(STORE_CROSSLANG_HEXADS_ENV);
        if let Some(v) = original {
            std::env::set_var(STORE_CROSSLANG_HEXADS_ENV, v);
        }
    }
}
