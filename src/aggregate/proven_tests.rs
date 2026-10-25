// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Ingest a `proven-tests` JSON run report (schema_version 1) as an aggregate
//! input kind.
//!
//! `proven-tests-and-benches` grades each test by three-tier provenance
//! (Actually-Proven / Provisionally-Proven / Unproven), where Actually-Proven
//! carries a proof ladder citing machine-checked theorems in real `.idr` files.
//! This module folds such a report into aggregate's vocabulary using the honest
//! mapping fixed in that repo's `docs/INTEROP-PANIC-ATTACK.adoc`:
//!
//!   * **Actually-Proven** — has a proof artifact (the ladder files). Expected
//!     to reconcile as [`ProofVerdict::Closed`]. Its cited `proof_file`s are the
//!     natural inputs to the ordinary `aggregate --proof` path.
//!   * **Provisionally-Proven** — type-safe framework + example/property
//!     evidence, but *no proof object*. Deliberately NOT treated as
//!     [`ProofVerdict::Holes`]: absence of a proof artifact is not the presence
//!     of a hole. Recorded as informational only.
//!   * **Unproven** — no artifact; informational only.
//!
//! The trust boundary is unchanged: panic-attack does not re-check the proofs;
//! a `Closed` reading is conditioned on the Idris checker's soundness.

use super::ProofVerdict;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

/// A cited proof step (only Actually-Proven entries carry these).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub description: String,
    #[serde(default)]
    pub proof_file: Option<String>,
    #[serde(default)]
    pub theorem: Option<String>,
}

/// One graded test entry in the run report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub test_id: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub aspect: Option<String>,
    /// "Actually-Proven" / "Provisionally-Proven" / "Unproven".
    pub provenance: String,
    #[serde(default)]
    pub proof_ladder: Vec<ProofStep>,
}

/// The run-report summary block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub actually_proven: usize,
    #[serde(default)]
    pub provisionally_proven: usize,
    #[serde(default)]
    pub unproven: usize,
    #[serde(default)]
    pub covered_cells: usize,
    #[serde(default)]
    pub cat_aspect_cells: usize,
    #[serde(default)]
    pub lattice_covered: usize,
}

/// A parsed `proven-tests` run report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenTestsReport {
    pub schema_version: u32,
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub summary: Summary,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// The three provenance tiers, parsed from the report's string labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportTier {
    ActuallyProven,
    ProvisionallyProven,
    Unproven,
}

impl ReportTier {
    /// Parse the report's tier label (the exact `Show ProvenStatus` strings).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Actually-Proven" => Some(ReportTier::ActuallyProven),
            "Provisionally-Proven" => Some(ReportTier::ProvisionallyProven),
            "Unproven" => Some(ReportTier::Unproven),
            _ => None,
        }
    }

    /// The honest aggregate reading of a tier. Only Actually-Proven maps to a
    /// proof verdict (`Closed`); the weaker tiers carry no artifact, so they
    /// map to `None` rather than being misread as `Holes`.
    pub fn to_verdict(self) -> Option<ProofVerdict> {
        match self {
            ReportTier::ActuallyProven => Some(ProofVerdict::Closed),
            ReportTier::ProvisionallyProven | ReportTier::Unproven => None,
        }
    }
}

impl FromStr for ProvenTestsReport {
    type Err = anyhow::Error;

    /// Parse a run report from JSON text, requiring schema version 1.
    ///
    /// # Errors
    /// Returns JSON deserialisation errors or an error if `schema_version` is not 1.
    fn from_str(text: &str) -> Result<Self> {
        let report: ProvenTestsReport =
            serde_json::from_str(text).context("parsing proven-tests run report")?;
        if report.schema_version != 1 {
            anyhow::bail!(
                "unsupported proven-tests report schema_version {} (expected 1)",
                report.schema_version
            );
        }
        Ok(report)
    }
}

impl ProvenTestsReport {
    /// Read a UTF-8 JSON run report from `path` and parse it as schema version 1.
    ///
    /// # Errors
    /// Returns file read errors (including invalid UTF-8), JSON deserialisation
    /// errors or an error if `schema_version` is not 1.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_str(&text)
    }

    /// The distinct `.idr` proof-ladder files cited by Actually-Proven entries.
    /// These are the natural inputs to the ordinary `aggregate --proof` path.
    pub fn actually_proven_ladder_files(&self) -> Vec<String> {
        let mut files: BTreeSet<String> = BTreeSet::new();
        for entry in &self.entries {
            if ReportTier::parse(&entry.provenance) == Some(ReportTier::ActuallyProven) {
                for step in &entry.proof_ladder {
                    if let Some(f) = &step.proof_file {
                        files.insert(f.clone());
                    }
                }
            }
        }
        files.into_iter().collect()
    }

    /// A one-line, honest note per entry, applying the tier→verdict mapping.
    pub fn notes(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|e| match ReportTier::parse(&e.provenance) {
                Some(ReportTier::ActuallyProven) => format!(
                    "{}: Actually-Proven → Closed ({} ladder step(s))",
                    e.test_id,
                    e.proof_ladder.len()
                ),
                Some(ReportTier::ProvisionallyProven) => {
                    format!(
                        "{}: Provisionally-Proven → informational (no proof artifact)",
                        e.test_id
                    )
                }
                Some(ReportTier::Unproven) => {
                    format!(
                        "{}: Unproven → informational (no proof artifact)",
                        e.test_id
                    )
                }
                None => format!(
                    "{}: unrecognised provenance tier {:?}",
                    e.test_id, e.provenance
                ),
            })
            .collect()
    }
}

/// A `proven-tests` run report as folded into an [`crate::aggregate::AggregateReport`].
///
/// This is the reciprocal of the framework's `scripts/emit-aggregate-inputs.sh`
/// (documented in `docs/INTEROP-PANIC-ATTACK.adoc` in that repository): instead
/// of exporting proof files to panic-attack, panic-attack reads the run report.
/// Both directions apply the same tier->verdict mapping, which lives in
/// [`ReportTier::to_verdict`].
///
/// `defects` is the honest part. A report can *say* anything; these are the
/// claims it makes that its own contents do not support — an Actually-Proven
/// entry with no ladder, a ladder step naming no file, a cited file that is not
/// present under the root, an unrecognised tier, a summary that disagrees with
/// the entries, or a report with no entries at all. An empty `defects` list is
/// therefore a positive claim, not a default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenTestsRecord {
    /// Path of the report that was ingested.
    pub path: std::path::PathBuf,
    /// BLAKE3 of the exact bytes ingested: a different report will not match.
    pub hash: super::HashRecord,
    /// Size of the report in bytes.
    pub bytes: u64,
    /// The report's own `suite` field.
    pub suite: String,
    /// Tier and coverage counts as the report stated them.
    pub summary: Summary,
    /// Distinct `.idr` files cited by Actually-Proven ladders.
    pub ladder_files: Vec<String>,
    /// One honest line per entry, applying the tier->verdict mapping.
    pub readings: Vec<String>,
    /// Unsupported claims; empty only when the report is self-consistent.
    pub defects: Vec<String>,
}

/// Read a run report, hash it, and check that its claims are backed by its own
/// contents.
///
/// `root` is the directory cited `proof_file` paths are resolved against — for
/// the framework's own reports that is the `proven-tests-and-benches` checkout.
/// It defaults to the report's parent directory, so a report colocated with the
/// sources it cites needs no extra configuration.
///
/// # Errors
/// Returns file read, BLAKE3 hashing and JSON parsing errors (including an
/// unsupported `schema_version`). Does *not* error on defects: it records them,
/// so a caller may report first and fail afterwards with
/// `AggregateConfig::fail_on_defect`.
pub fn ingest(path: &Path, root: Option<&Path>) -> Result<ProvenTestsRecord> {
    let report = ProvenTestsReport::from_path(path)?;
    let (hash, bytes) = super::hash_file(path)?;
    let base = root.map(Path::to_path_buf).unwrap_or_else(|| {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    let mut defects = Vec::new();
    let mut ladder_files: Vec<String> = Vec::new();
    let mut counted_actually_proven = 0usize;

    if report.entries.is_empty() {
        defects.push("report contains no entries: an empty run proves nothing".to_string());
    }

    for entry in &report.entries {
        match ReportTier::parse(&entry.provenance) {
            None => defects.push(format!(
                "{}: unrecognised provenance tier {:?} (expected Actually-Proven, Provisionally-Proven or Unproven)",
                entry.test_id, entry.provenance
            )),
            Some(ReportTier::ActuallyProven) => {
                counted_actually_proven += 1;
                if entry.proof_ladder.is_empty() {
                    defects.push(format!(
                        "{}: claims Actually-Proven with an empty proof ladder",
                        entry.test_id
                    ));
                }
                for step in &entry.proof_ladder {
                    match &step.proof_file {
                        None => defects.push(format!(
                            "{}: ladder step {:?} cites no proof file",
                            entry.test_id, step.description
                        )),
                        Some(file) => {
                            let candidate = base.join(file);
                            if !candidate.is_file() {
                                defects.push(format!(
                                    "{}: cited proof file {} was not found under {}",
                                    entry.test_id,
                                    file,
                                    base.display()
                                ));
                            }
                            if !ladder_files.iter().any(|f| f == file) {
                                ladder_files.push(file.clone());
                            }
                        }
                    }
                }
            }
            Some(ReportTier::ProvisionallyProven | ReportTier::Unproven) => {}
        }
    }

    if report.summary.actually_proven != counted_actually_proven {
        defects.push(format!(
            "summary claims {} Actually-Proven entr{}, entries carry {}",
            report.summary.actually_proven,
            if report.summary.actually_proven == 1 {
                "y"
            } else {
                "ies"
            },
            counted_actually_proven
        ));
    }
    if report.summary.covered_cells > report.summary.cat_aspect_cells {
        defects.push(format!(
            "summary claims {} covered cells of a {} cell lattice",
            report.summary.covered_cells, report.summary.cat_aspect_cells
        ));
    }

    Ok(ProvenTestsRecord {
        path: path.to_path_buf(),
        hash,
        bytes,
        suite: report.suite.clone(),
        summary: report.summary.clone(),
        ladder_files,
        readings: report.notes(),
        defects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "schema_version": 1,
      "suite": "proven-tests",
      "summary": {"passed": 3, "total": 3, "actually_proven": 1,
                  "provisionally_proven": 1, "unproven": 1,
                  "covered_cells": 35, "cat_aspect_cells": 238, "lattice_covered": 35},
      "entries": [
        {"test_id": "tropical-laws", "category": "Proof-Regression",
         "aspect": "Dependability", "provenance": "Actually-Proven",
         "proof_ladder": [
           {"description": "comm", "proof_file": "src/ProvenTests/Tropical.idr", "theorem": "oplusComm"},
           {"description": "assoc", "proof_file": "src/ProvenTests/Tropical.idr", "theorem": "oplusAssoc"}
         ],
         "result": "passed"},
        {"test_id": "typesafe-tropical", "provenance": "Provisionally-Proven",
         "proof_ladder": [], "result": "passed"},
        {"test_id": "smoke-show", "provenance": "Unproven",
         "proof_ladder": [], "result": "passed"}
      ]
    }"#;

    #[test]
    fn parses_schema_v1() {
        let r: ProvenTestsReport = SAMPLE.parse().expect("parse");
        assert_eq!(r.schema_version, 1);
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.summary.actually_proven, 1);
        assert_eq!(r.summary.covered_cells, 35);
    }

    #[test]
    fn tier_mapping_is_honest() {
        // Only Actually-Proven becomes a proof verdict; the weaker tiers do NOT
        // become Holes.
        assert_eq!(
            ReportTier::ActuallyProven.to_verdict(),
            Some(ProofVerdict::Closed)
        );
        assert_eq!(ReportTier::ProvisionallyProven.to_verdict(), None);
        assert_eq!(ReportTier::Unproven.to_verdict(), None);
    }

    #[test]
    fn extracts_distinct_actually_proven_ladder_files() {
        let r = ProvenTestsReport::from_str(SAMPLE).unwrap();
        let files = r.actually_proven_ladder_files();
        // two ladder steps cite the same file → one distinct entry
        assert_eq!(files, vec!["src/ProvenTests/Tropical.idr".to_string()]);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let bad = SAMPLE.replace("\"schema_version\": 1", "\"schema_version\": 2");
        assert!(ProvenTestsReport::from_str(&bad).is_err());
    }

    #[test]
    fn unknown_tier_is_flagged_not_panicked() {
        assert_eq!(ReportTier::parse("Sorta-Proven"), None);
        let weird = SAMPLE.replace("\"Unproven\"", "\"Sorta-Proven\"");
        let r = ProvenTestsReport::from_str(&weird).unwrap();
        // notes() surfaces the unrecognised tier rather than crashing
        assert!(r
            .notes()
            .iter()
            .any(|n| n.contains("unrecognised provenance tier")));
    }

    #[test]
    fn ingest_flags_an_actually_proven_claim_with_no_ladder() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(
            &report,
            r#"{"schema_version":1,"suite":"proven-tests","summary":{"actually_proven":1},
                "entries":[{"test_id":"claims-proof","provenance":"Actually-Proven",
                            "proof_ladder":[],"result":"passed"}]}"#,
        )
        .unwrap();
        let record = ingest(&report, None).expect("ingest");
        assert!(record
            .defects
            .iter()
            .any(|d| d.contains("empty proof ladder")));
        assert!(record.ladder_files.is_empty());
    }

    #[test]
    fn ingest_flags_a_cited_proof_file_that_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(
            &report,
            r#"{"schema_version":1,"suite":"proven-tests",
                "summary":{"actually_proven":1,"covered_cells":1,"cat_aspect_cells":238},
                "entries":[{"test_id":"cites-proof","provenance":"Actually-Proven",
                            "proof_ladder":[{"description":"comm","proof_file":"src/ProvenTests/Tropical.idr"}],
                            "result":"passed"}]}"#,
        )
        .unwrap();
        let record = ingest(&report, None).expect("ingest");
        assert!(
            record
                .defects
                .iter()
                .any(|d| d.contains("was not found under")),
            "{:?}",
            record.defects
        );
        assert_eq!(
            record.ladder_files,
            vec!["src/ProvenTests/Tropical.idr".to_string()]
        );
    }

    #[test]
    fn ingest_accepts_a_self_consistent_report() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/Tropical.idr"), "-- proof\n").unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(
            &report,
            r#"{"schema_version":1,"suite":"proven-tests",
                "summary":{"passed":2,"total":2,"actually_proven":1,"provisionally_proven":1,
                           "covered_cells":3,"cat_aspect_cells":238,"lattice_covered":3},
                "entries":[{"test_id":"tropical-laws","provenance":"Actually-Proven",
                            "proof_ladder":[{"description":"comm","proof_file":"src/Tropical.idr",
                                             "theorem":"oplusComm"}],"result":"passed"},
                           {"test_id":"smoke","provenance":"Unproven","proof_ladder":[],
                            "result":"passed"}]}"#,
        )
        .unwrap();
        let record = ingest(&report, Some(dir.path())).expect("ingest");
        assert!(record.defects.is_empty(), "{:?}", record.defects);
        assert_eq!(record.suite, "proven-tests");
        assert_eq!(record.summary.passed, 2);
        assert!(record.hash.hex.len() == 64);
    }

    #[test]
    fn ingest_flags_a_summary_that_disagrees_with_the_entries() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(
            &report,
            r#"{"schema_version":1,"summary":{"actually_proven":2},
                "entries":[{"test_id":"one","provenance":"Provisionally-Proven","proof_ladder":[]}]}"#,
        )
        .unwrap();
        let record = ingest(&report, None).expect("ingest");
        assert!(record
            .defects
            .iter()
            .any(|d| d.contains("summary claims 2")));
    }
}
