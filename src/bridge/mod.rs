// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

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
//! Design document: docs/patch-bridge-design.adoc

pub mod classify;
pub mod intelligence;
pub mod lockfile;
pub mod reachability;
pub mod registry;

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
    /// For `PhantomTransitive`: the direct dep (declared in Cargo.toml) whose
    /// dependency closure pulls in this crate, best-effort. `None` if the
    /// parent could not be identified or if status is not `PhantomTransitive`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_dep: Option<String>,
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
///
/// `PhantomDeclared` and `PhantomTransitive` are both informational, but
/// distinguish the remediation path:
///
/// - **PhantomDeclared** — crate IS listed in the project's `Cargo.toml`
///   (root or workspace member) but no `use <crate>` site exists. Fix:
///   strip the manifest line (`cargo machete --fix` or manual removal).
/// - **PhantomTransitive** — crate is NOT in any Cargo.toml; it's pulled
///   in by a parent dep. Local stripping is impossible; the fix requires
///   bumping the parent dependency past the affected version.
///
/// JSON wire format uses `phantom-declared` / `phantom-transitive` /
/// `unreachable` / `reachable`. See `schema_version` 0.3.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReachabilityStatus {
    /// Declared in Cargo.toml but never imported — the manifest entry is
    /// genuinely unused. Strip the dep to eliminate the CVE entirely.
    PhantomDeclared,
    /// NOT declared in any Cargo.toml; pulled in transitively by a parent
    /// crate. Local strip is impossible; fix the parent.
    PhantomTransitive,
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

/// Whether the report actually queried a vulnerability feed.
///
/// `OfflineUnavailable` explicitly means the CVE list is empty because the
/// feed was not queried. It must never be interpreted as a clean result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnerabilityDataStatus {
    Queried,
    NoDependencies,
    OfflineUnavailable,
}

/// The complete Patch Bridge triage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeReport {
    /// Schema version for forward compatibility
    pub schema_version: String,
    /// `offline-unavailable` means NO vulnerability data was obtained, not zero known CVEs.
    #[serde(default = "default_vulnerability_data_status")]
    pub vulnerability_data: VulnerabilityDataStatus,
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

/// Treat reports without a `vulnerability_data` field as having queried a feed.
fn default_vulnerability_data_status() -> VulnerabilityDataStatus {
    VulnerabilityDataStatus::Queried
}

impl BridgeReport {
    /// Create a report with no assessed CVEs and zero finding counts.
    ///
    /// `total_deps` supplies the dependency count. No feed is queried here;
    /// `vulnerability_data` defaults to `Queried`, so callers must change it
    /// when reporting offline data or a project with no dependencies.
    pub fn empty(project: &Path, total_deps: usize) -> Self {
        Self {
            schema_version: "0.3.0".to_string(),
            vulnerability_data: VulnerabilityDataStatus::Queried,
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
        self.mitigated = self
            .cves
            .iter()
            .filter(|c| c.classification == Classification::Mitigable)
            .count();
        self.unmitigable = self
            .cves
            .iter()
            .filter(|c| c.classification == Classification::Unmitigable)
            .count();
        self.informational = self
            .cves
            .iter()
            .filter(|c| c.classification == Classification::Informational)
            .count();
        self.vulnerable_dependencies = self.cves.len();
    }
}

// ============================================================================
// Top-level triage orchestrator
// ============================================================================

/// Run the full Patch Bridge triage on a project directory.
///
/// Recursively discovers supported lockfiles and merges their dependencies,
/// then queries OSV, checks Rust import reachability and classifies findings.
/// A parsed result with no dependencies returns an empty report marked
/// `NoDependencies` without querying OSV.
///
/// With `offline = true`, skips OSV and returns no CVEs, marking reports with
/// dependencies as `OfflineUnavailable`; this is not evidence of zero
/// vulnerabilities.
/// Unreadable source files are skipped during reachability scanning.
///
/// # Errors
/// Returns an error if directory traversal fails, no supported lockfile is
/// found, or any discovered lockfile fails to parse. Propagates OSV request,
/// response-read and JSON errors.
pub fn triage(project_dir: &Path, offline: bool) -> anyhow::Result<BridgeReport> {
    triage_with_discovery(project_dir, offline, None)
}

/// Run triage using explicitly named lockfiles instead of discovery.
///
/// Paths are used as supplied, relative to the process working directory when
/// relative, rather than resolved against `project_dir`.
///
/// # Errors
/// Propagates [`lockfile::parse_lockfiles`] and triage errors. Empty input is
/// rejected as having no lockfiles; successfully parsed files with no external
/// dependencies return a report marked `NoDependencies`.
pub fn triage_with_lockfiles(
    project_dir: &Path,
    offline: bool,
    paths: &[PathBuf],
) -> anyhow::Result<BridgeReport> {
    let discovery = lockfile::parse_lockfiles(paths)?;
    triage_with_discovery(project_dir, offline, Some(discovery))
}

/// Assess `explicit` discovery, or discover recursively when it is `None`.
/// Uses the offline and report-status behaviour described by [`triage`].
///
/// # Errors
/// Rejects missing lockfiles or recorded parse failures and propagates
/// discovery traversal errors and OSV request, response-read and JSON errors.
fn triage_with_discovery(
    project_dir: &Path,
    offline: bool,
    explicit: Option<lockfile::LockfileDiscovery>,
) -> anyhow::Result<BridgeReport> {
    // Distinguish no lockfile (unknown dependency surface) from a valid
    // lockfile containing zero external dependencies (a complete answer).
    let discovery = match explicit {
        Some(discovery) => discovery,
        None => lockfile::discover_and_parse(project_dir)?,
    };
    if !discovery.has_lockfiles() {
        anyhow::bail!(
            "No supported lockfile found in {}. Supported: {}.",
            project_dir.display(),
            lockfile::SUPPORTED_LOCKFILES
        );
    }
    // A lockfile that exists but cannot be parsed is not a clean result.
    if !discovery.unreadable.is_empty() {
        anyhow::bail!(
            "Could not parse {} lockfile(s) under {}; refusing to report a clean result: {}",
            discovery.unreadable.len(),
            project_dir.display(),
            discovery
                .unreadable
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let total_deps = discovery.len();

    if discovery.is_empty() {
        let mut report = BridgeReport::empty(project_dir, 0);
        report.vulnerability_data = VulnerabilityDataStatus::NoDependencies;
        return Ok(report);
    }
    let deps = &discovery.dependencies;

    // Step 2: Query for vulnerabilities
    let vulns = if offline {
        Vec::new() // Offline mode: no local advisory DB is queried or available.
    } else {
        intelligence::query_osv_batch(deps)?
    };

    if vulns.is_empty() {
        let mut report = BridgeReport::empty(project_dir, total_deps);
        if offline {
            report.vulnerability_data = VulnerabilityDataStatus::OfflineUnavailable;
        }
        return Ok(report);
    }

    // Direct-vs-transitive lookup tables for discovered Cargo workspaces.
    // Collected once (not per-CVE) to avoid re-parsing the manifest for
    // every vulnerable dep — see #47.
    let (direct_deps, parent_map) = discovery.cargo_context(project_dir);

    // Step 3 & 4: For each vuln, check reachability and classify
    let mut assessed = Vec::new();
    for vuln in vulns {
        let evidence = reachability::check_reachability_with_manifest(
            project_dir,
            &vuln.package,
            &direct_deps,
            &parent_map,
        )?;
        let (classification, rationale, action) = classify::classify(&vuln, &evidence);

        assessed.push(AssessedCve {
            vulnerability: vuln,
            reachability: evidence,
            classification,
            rationale,
            action,
        });
    }

    let mut report = BridgeReport {
        schema_version: "0.3.0".to_string(),
        vulnerability_data: VulnerabilityDataStatus::Queried,
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

#[cfg(test)]
mod triage_tests {
    use super::*;

    #[test]
    fn dependency_free_lockfile_returns_valid_empty_report() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("Cargo.lock"), "version = 4\n")?;

        let report = triage(dir.path(), true)?;
        assert_eq!(report.total_dependencies, 0);
        assert!(report.cves.is_empty());
        assert_eq!(
            report.vulnerability_data,
            VulnerabilityDataStatus::NoDependencies
        );
        Ok(())
    }

    #[test]
    fn missing_lockfile_is_not_confused_with_empty_lockfile() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let error = triage(dir.path(), true).expect_err("missing lockfile must fail");
        assert!(error.to_string().contains("No supported lockfile found"));
        Ok(())
    }

    #[test]
    fn offline_report_marks_vulnerability_data_unavailable() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )?;

        let report = triage(dir.path(), true)?;
        assert_eq!(report.total_dependencies, 1);
        assert!(report.cves.is_empty());
        assert_eq!(
            report.vulnerability_data,
            VulnerabilityDataStatus::OfflineUnavailable
        );
        Ok(())
    }
    #[test]
    fn structurally_valid_empty_lockfiles_report_no_dependencies() -> anyhow::Result<()> {
        for (name, content) in [
            ("Cargo.lock", "version = 3\n"),
            ("mix.lock", "%{}\n"),
            (
                "package-lock.json",
                r#"{"name":"empty","lockfileVersion":1}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":1,"dependencies":{}}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":2,"packages":{}}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"}}}"#,
            ),
            ("requirements.txt", "# No external dependencies\n\n"),
        ] {
            let dir = tempfile::TempDir::new()?;
            let path = dir.path().join(name);
            std::fs::write(&path, content)?;
            for report in [
                triage(dir.path(), true)?,
                triage_with_lockfiles(dir.path(), true, &[path])?,
            ] {
                assert_eq!(
                    report.vulnerability_data,
                    VulnerabilityDataStatus::NoDependencies,
                    "{name}: {content}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_or_unsupported_lockfiles_never_report_no_dependencies() -> anyhow::Result<()> {
        for (name, content) in [
            ("Cargo.lock", ""),
            ("Cargo.lock", "version = 4\nnot toml"),
            ("Cargo.lock", "version = 4\npackage = 1"),
            ("Cargo.lock", "version = 4\n[[package]]\nname = \"broken\""),
            ("Cargo.lock", "[[package]]\nname = \"broken\"\nversion = 4"),
            ("Cargo.lock", "version = 4\n[packages]"),
            ("mix.lock", ""),
            ("mix.lock", "%{\ninvalid entry\n}"),
            ("mix.lock", "%{\n\"broken\": {:hex, :broken, \"1.0\"\n}"),
            ("mix.lock", "%{\n\"broken\": {:hex, :broken, 1.0},\n}"),
            ("package-lock.json", "{}"),
            ("package-lock.json", "[]"),
            ("package-lock.json", "null"),
            (
                "package-lock.json",
                r#"{"lockfileVersion":99,"packages":{}}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":[]}"#,
            ),
            ("package-lock.json", r#"{"lockfileVersion":3}"#),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"node_modules/broken":{}}}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":1,"dependencies":{"broken":{"version":42}}}"#,
            ),
            ("requirements.txt", "not a requirement"),
            ("requirements.txt", "requests>=2.0"),
            ("requirements.txt", "-r other.txt"),
            ("requirements.txt", "requests=="),
            ("requirements.txt", "==1.0"),
            ("requirements.txt", "requests===1.0"),
        ] {
            let dir = tempfile::TempDir::new()?;
            let path = dir.path().join(name);
            std::fs::write(&path, content)?;
            let error = triage(dir.path(), true).expect_err(content);
            assert!(
                error.to_string().contains("Could not parse"),
                "{name}: {content}: {error}"
            );
            assert!(
                triage_with_lockfiles(dir.path(), true, &[path]).is_err(),
                "{name}: {content}"
            );
        }
        Ok(())
    }

    #[test]
    fn explicit_lockfile_does_not_trigger_recursive_discovery() -> anyhow::Result<()> {
        let project = tempfile::TempDir::new()?;
        std::fs::write(project.path().join("Cargo.lock"), "broken")?;
        let external = tempfile::TempDir::new()?;
        let path = external.path().join("requirements.txt");
        std::fs::write(&path, "requests==2.0.0\n")?;
        let report = triage_with_lockfiles(project.path(), true, &[path])?;
        assert_eq!(report.total_dependencies, 1);
        assert_eq!(
            report.vulnerability_data,
            VulnerabilityDataStatus::OfflineUnavailable
        );
        Ok(())
    }

    #[test]
    fn missing_project_directory_is_a_traversal_error() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let error = triage(&dir.path().join("missing"), true).unwrap_err();
        assert!(error.to_string().contains("Failed to traverse"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_subdirectory_prevents_no_dependencies_report() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("Cargo.lock"), "version = 4\n")?;
        let blocked = dir.path().join("nested");
        std::fs::create_dir(&blocked)?;
        std::fs::write(blocked.join("requirements.txt"), "requests==2.0.0\n")?;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))?;
        // Root can bypass mode bits; exercise this case when the OS enforces them.
        let enforced = std::fs::read_dir(&blocked).is_err();
        let result = triage(dir.path(), true);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))?;
        if enforced {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to traverse"));
        }
        Ok(())
    }
}
