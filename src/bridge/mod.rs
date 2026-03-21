// SPDX-License-Identifier: PMPL-1.0-or-later

//! Patch Bridge — CVE mitigation lifecycle for upstream vulnerabilities.
//!
//! Bridges the gap between CVE disclosure and upstream fix by providing:
//! - Multi-source CVE intelligence (OSV API for MVP, expandable to NVD/GHSA/VirusTotal)
//! - Reachability analysis (phantom dependency detection via import scanning)
//! - Three-way classification: Mitigable / Unmitigable / Informational
//! - Mitigation registry for lifecycle tracking (apply → monitor → retire)
//!
//! This module extends panic-attack with `bridge` subcommands. The core tool
//! remains standalone — PanLL panel and BoJ cartridge are optional integrations.
//!
//! Design document: docs/patch-bridge-design.md

pub mod intelligence;
pub mod reachability;
pub mod classify;
pub mod registry;
pub mod lockfile;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ============================================================================
// Core types
// ============================================================================

/// A known vulnerability from a CVE feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Advisory ID (e.g., "RUSTSEC-2023-0071", "GHSA-xxxx-xxxx")
    pub id: String,
    /// CVE ID if assigned (e.g., "CVE-2023-49092")
    pub cve: Option<String>,
    /// Human-readable summary
    pub summary: String,
    /// Affected package name
    pub package: String,
    /// Affected version in this project
    pub version: String,
    /// CVSS severity score (0.0–10.0)
    pub severity: Option<f64>,
    /// Severity label derived from CVSS
    pub severity_label: SeverityLabel,
    /// Fixed version(s) if available
    pub fixed_versions: Vec<String>,
    /// Whether a semver-compatible fix exists for the current pin
    pub semver_fix_available: bool,
    /// Source tier that reported this vulnerability
    pub source_tier: SourceTier,
    /// URL references
    pub references: Vec<String>,
}

/// Severity label for display and triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLabel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl SeverityLabel {
    /// Derive from CVSS score.
    pub fn from_cvss(score: f64) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Intelligence source tier (Ground News model for CVEs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceTier {
    /// Standard advisories: NVD, GHSA, OSV, vendor
    Tier1,
    /// Community intelligence: VirusTotal, ExploitDB, language-specific
    Tier2,
    /// Long tail: oss-security, academic, upstream commits
    Tier3,
}

/// A dependency extracted from a lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedDependency {
    /// Package name
    pub name: String,
    /// Locked version
    pub version: String,
    /// Ecosystem (e.g., "crates.io", "npm", "hex")
    pub ecosystem: String,
    /// Which workspace members declare this dependency (Cargo.toml paths)
    pub declared_by: Vec<PathBuf>,
}

/// Reachability evidence for a dependency in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityEvidence {
    /// Whether any source file imports this dependency
    pub is_imported: bool,
    /// Files that import the dependency, with line numbers
    pub import_sites: Vec<ImportSite>,
    /// Classification based on import analysis
    pub status: ReachabilityStatus,
}

/// Where a dependency is imported in source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSite {
    /// File path relative to project root
    pub file: PathBuf,
    /// Line number of the import
    pub line: usize,
    /// The import statement text
    pub statement: String,
}

/// Whether a dependency is reachable from application code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityStatus {
    /// Declared in manifest but never imported — phantom dependency
    Phantom,
    /// Imported but no data flow to vulnerable code path (Phase 2: kanren taint)
    Unreachable,
    /// Imported and potentially reachable
    Reachable,
}

/// Three-way CVE classification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    /// A semver-compatible fix exists or a control can be layered
    Mitigable,
    /// No fix available and dependency is reachable
    Unmitigable,
    /// CVE exists but dependency is phantom/unreachable in this codebase
    Informational,
}

/// A fully assessed CVE with classification and evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessedCve {
    /// The vulnerability details
    pub vulnerability: Vulnerability,
    /// Reachability evidence
    pub reachability: ReachabilityEvidence,
    /// Final classification
    pub classification: Classification,
    /// Human-readable explanation of the classification
    pub rationale: String,
    /// Suggested action
    pub action: String,
}

/// The complete Patch Bridge triage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeReport {
    /// Schema version for forward compatibility
    pub schema_version: String,
    /// Project path that was assessed
    pub project: PathBuf,
    /// Total dependencies scanned
    pub total_dependencies: usize,
    /// Dependencies with known vulnerabilities
    pub vulnerable_dependencies: usize,
    /// All assessed CVEs with classifications
    pub cves: Vec<AssessedCve>,
    /// Count of mitigable CVEs
    pub mitigated: usize,
    /// Count of unmitigable CVEs
    pub unmitigable: usize,
    /// Count of concatenative risks (Phase 2)
    pub concatenative: usize,
    /// Count of informational CVEs (phantom/unreachable)
    pub informational: usize,
}

impl BridgeReport {
    /// Create an empty report for a project with no vulnerabilities.
    pub fn empty(project: &Path, total_deps: usize) -> Self {
        Self {
            schema_version: "0.1.0".to_string(),
            project: project.to_path_buf(),
            total_dependencies: total_deps,
            vulnerable_dependencies: 0,
            cves: Vec::new(),
            mitigated: 0,
            unmitigable: 0,
            concatenative: 0,
            informational: 0,
        }
    }

    /// Recompute counts from the CVE list.
    pub fn recount(&mut self) {
        self.mitigated = self.cves.iter().filter(|c| c.classification == Classification::Mitigable).count();
        self.unmitigable = self.cves.iter().filter(|c| c.classification == Classification::Unmitigable).count();
        self.informational = self.cves.iter().filter(|c| c.classification == Classification::Informational).count();
        self.vulnerable_dependencies = self.cves.len();
    }
}

// ============================================================================
// Top-level triage orchestrator
// ============================================================================

/// Run the full Patch Bridge triage on a project directory.
///
/// 1. Parse lockfile to extract dependencies
/// 2. Query OSV API for known vulnerabilities
/// 3. For each vulnerable dep, check reachability (import scanning)
/// 4. Classify: mitigable / unmitigable / informational
/// 5. Return structured report
pub fn triage(project_dir: &Path, offline: bool) -> anyhow::Result<BridgeReport> {
    // Step 1: Parse lockfile
    let lockfile_path = project_dir.join("Cargo.lock");
    if !lockfile_path.exists() {
        anyhow::bail!(
            "No Cargo.lock found in {}. Patch Bridge MVP supports Rust projects only.",
            project_dir.display()
        );
    }
    let deps = lockfile::parse_cargo_lock(&lockfile_path)?;
    let total_deps = deps.len();

    if deps.is_empty() {
        return Ok(BridgeReport::empty(project_dir, 0));
    }

    // Step 2: Query for vulnerabilities
    let vulns = if offline {
        Vec::new() // Offline mode: skip API, rely on local advisory DB
    } else {
        intelligence::query_osv_batch(&deps)?
    };

    if vulns.is_empty() {
        return Ok(BridgeReport::empty(project_dir, total_deps));
    }

    // Step 3 & 4: For each vuln, check reachability and classify
    let mut assessed = Vec::new();
    for vuln in vulns {
        let evidence = reachability::check_reachability(project_dir, &vuln.package)?;
        let (classification, rationale, action) =
            classify::classify(&vuln, &evidence);

        assessed.push(AssessedCve {
            vulnerability: vuln,
            reachability: evidence,
            classification,
            rationale,
            action,
        });
    }

    let mut report = BridgeReport {
        schema_version: "0.1.0".to_string(),
        project: project_dir.to_path_buf(),
        total_dependencies: total_deps,
        vulnerable_dependencies: 0,
        cves: assessed,
        mitigated: 0,
        unmitigable: 0,
        concatenative: 0,
        informational: 0,
    };
    report.recount();

    Ok(report)
}
