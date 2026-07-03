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

impl ProvenTestsReport {
    /// Parse a run report from JSON text.
    pub fn from_str(text: &str) -> Result<Self> {
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

    /// Parse a run report from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
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
                    format!("{}: Provisionally-Proven → informational (no proof artifact)", e.test_id)
                }
                Some(ReportTier::Unproven) => {
                    format!("{}: Unproven → informational (no proof artifact)", e.test_id)
                }
                None => format!("{}: unrecognised provenance tier {:?}", e.test_id, e.provenance),
            })
            .collect()
    }
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
        let r = ProvenTestsReport::from_str(SAMPLE).expect("parse");
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
        assert!(r.notes().iter().any(|n| n.contains("unrecognised provenance tier")));
    }
}
