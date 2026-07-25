// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Cargo-deny scanner integration
//
// Emits weak_points for cargo-deny findings (license policy, advisories, banned deps)
// as specified in panic-attack#101. Output is detection-only per estate policy
// feedback_no_automated_licence_edits.

use crate::types::{Severity, WeakPoint, WeakPointCategory};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Configuration for cargo-deny scanner
#[derive(Debug, Clone)]
pub struct CargoDenyConfig {
    /// Path to the workspace root (contains Cargo.toml)
    pub workspace_root: PathBuf,
    /// Optional path to deny.toml (defaults to workspace_root/deny.toml)
    pub deny_toml: Option<PathBuf>,
    /// Output format: "json" or "sarif"
    #[cfg(feature = "sarif")]
    pub format: String,
    #[cfg(not(feature = "sarif"))]
    pub format: String,
    /// Fail on warnings (--fail-on-warnings flag)
    pub fail_on_warnings: bool,
    /// Additional cargo deny flags
    pub extra_args: Vec<String>,
}

impl Default for CargoDenyConfig {
    fn default() -> Self {
        CargoDenyConfig {
            workspace_root: PathBuf::new(),
            deny_toml: None,
            format: "json".to_string(),
            fail_on_warnings: false,
            extra_args: Vec::new(),
        }
    }
}

/// Severity level from cargo-deny (error > warning > note)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DenySeverity {
    Error,
    Warning,
    Note,
}

impl From<DenySeverity> for Severity {
    fn from(s: DenySeverity) -> Severity {
        match s {
            DenySeverity::Error => Severity::High,
            DenySeverity::Warning => Severity::Medium,
            DenySeverity::Note => Severity::Low,
        }
    }
}

/// cargo-deny diagnostic structure (simplified for JSON output)
#[derive(Debug, Clone, Deserialize)]
pub struct DenyDiagnostic {
    pub message: String,
    pub severity: Option<String>,
    pub code: Option<String>,
    pub location: Option<DenyLocation>,
}

/// Location information from cargo-deny
#[derive(Debug, Clone, Deserialize)]
pub struct DenyLocation {
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

/// Root structure for cargo-deny JSON output
#[derive(Debug, Clone, Deserialize)]
pub struct DenyOutput {
    pub diagnostics: Vec<DenyDiagnostic>,
}

/// Convert cargo-deny severity string to our enum
fn parse_deny_severity(s: &str) -> DenySeverity {
    match s.to_lowercase().as_str() {
        "error" => DenySeverity::Error,
        "warning" => DenySeverity::Warning,
        _ => DenySeverity::Note,
    }
}

/// Map cargo-deny diagnostic code to WeakPointCategory
fn code_to_category(code: &str) -> WeakPointCategory {
    // cargo-deny uses advisory IDs like RUSTSEC-2021-0001
    // and ban IDs from deny.toml
    if code.starts_with("RUSTSEC-") || code.starts_with("CVE-") || code.contains("advisory") {
        WeakPointCategory::Advisory
    } else if code.contains("banned") || code.contains("ban") {
        WeakPointCategory::BannedDep
    } else if code.contains("license") || code.contains("License") {
        WeakPointCategory::LicensePolicy
    } else if code.contains("source") || code.contains("unknown") {
        WeakPointCategory::UnknownSource
    } else {
        // Default to Advisory for generic security issues
        WeakPointCategory::Advisory
    }
}

/// Run cargo-deny check and parse output
pub fn run_cargo_deny(config: &CargoDenyConfig) -> Result<Vec<WeakPoint>> {
    let workspace_root = &config.workspace_root;
    
    // Build cargo deny command
    let mut cmd = Command::new("cargo");
    cmd.arg("deny")
        .arg("check")
        .arg("--format")
        .arg(&config.format)
        .current_dir(workspace_root);
    
    // Add optional flags
    if config.fail_on_warnings {
        cmd.arg("--fail-on-warnings");
    }
    
    // Add extra args
    for arg in &config.extra_args {
        cmd.arg(arg);
    }
    
    // Execute command
    let output = cmd.output().with_context(|| {
        format!(
            "failed to execute cargo deny in {}",
            workspace_root.display()
        )
    })?;
    
    // Check exit status - cargo-deny returns non-zero on failures
    // but we still want to parse the output
    if !output.status.success() {
        // This is expected when there are violations - we still parse them
        log::warn!(
            "cargo deny check failed with exit code {:?} in {}",
            output.status.code(),
            workspace_root.display()
        );
    }
    
    // Parse JSON output
    let stdout = String::from_utf8(output.stdout)
        .with_context(|| "cargo deny output is not valid UTF-8")?;
    
    let deny_output: DenyOutput = serde_json::from_str(&stdout)
        .with_context(|| "failed to parse cargo deny JSON output")?;
    
    // Convert diagnostics to WeakPoints
    let mut weak_points = Vec::new();
    for diagnostic in deny_output.diagnostics {
        let severity = diagnostic.severity
            .map(|s| parse_deny_severity(&s).into())
            .unwrap_or(Severity::Medium);
        
        let category = diagnostic.code
            .map(|c| code_to_category(&c))
            .unwrap_or(WeakPointCategory::Advisory);
        
        let location = diagnostic.location.map(|loc| {
            if let (Some(ref file), Some(line)) = (&loc.file, loc.line) {
                Some(format!("{}:{}", file, line))
            } else if let Some(ref file) = loc.file {
                Some(file.clone())
            } else {
                None
            }
        }).flatten();
        
        // Parse file and line from location string
        let (file, line) = if let Some(ref loc) = location {
            if let Some((f, l)) = loc.rsplit_once(':') {
                if let Ok(ln) = l.parse::<u32>() {
                    (Some(f.to_string()), Some(ln))
                } else {
                    (Some(loc.clone()), None)
                }
            } else {
                (Some(loc.clone()), None)
            }
        } else {
            (None, None)
        };
        
        let weak_point = WeakPoint {
            category,
            location: location.clone(),
            file,
            line,
            severity,
            description: diagnostic.message.clone(),
            recommended_attack: Vec::new(), // Will be populated by downstream
            suppressed: false,
            test_context: None,
        };
        
        weak_points.push(weak_point);
    }
    
    Ok(weak_points)
}

/// cargo-deny specific configuration for metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoDenyMetadata {
    /// Flag indicating this finding should not trigger auto-remediation
    /// Per estate policy feedback_no_automated_licence_edits
    pub do_not_automate: bool,
    /// The cargo-deny rule/check that triggered this finding
    pub deny_check: Option<String>,
    /// The crate/dependency that triggered this finding
    pub dependency: Option<String>,
    /// The version of the dependency
    pub version: Option<String>,
}

impl Default for CargoDenyMetadata {
    fn default() -> Self {
        CargoDenyMetadata {
            do_not_automate: true, // Always true for cargo-deny findings
            deny_check: None,
            dependency: None,
            version: None,
        }
    }
}

/// Extended WeakPoint with cargo-deny specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoDenyWeakPoint {
    #[serde(flatten)]
    pub weak_point: WeakPoint,
    #[serde(default)]
    pub cargo_deny_metadata: CargoDenyMetadata,
}

impl From<WeakPoint> for CargoDenyWeakPoint {
    fn from(wp: WeakPoint) -> Self {
        CargoDenyWeakPoint {
            weak_point: wp,
            cargo_deny_metadata: CargoDenyMetadata::default(),
        }
    }
}

/// Parse cargo-deny SARIF output (alternative to JSON)
#[cfg(feature = "sarif")]
pub fn parse_sarif_output(sarif_json: &str) -> Result<Vec<WeakPoint>> {
    use serde_json::Value;
    
    let v: Value = serde_json::from_str(sarif_json)?;
    
    // SARIF structure: { runs: [{ results: [{ ... }] }] }
    let runs = v["runs"].as_array().ok_or_else(|| anyhow!("no runs in SARIF"))?;
    let mut weak_points = Vec::new();
    
    for run in runs {
        let results = run["results"].as_array().ok_or_else(|| anyhow!("no results in SARIF run"))?;
        for result in results {
            let message = result["message"]["text"].as_str()
                .or_else(|| result["message"].as_str())
                .unwrap_or("Unknown cargo-deny finding").to_string();
            
            let severity_str = result["level"].as_str().unwrap_or("warning");
            let severity = parse_deny_severity(severity_str).into();
            
            let rule_id = result["ruleId"].as_str().map(|s| s.to_string());
            let category = rule_id
                .as_ref()
                .map(|c| code_to_category(c))
                .unwrap_or(WeakPointCategory::Advisory);
            
            let locations = result["locations"].as_array();
            let (location, file, line) = if let Some(locs) = locations {
                if !locs.is_empty() {
                    let loc = &locs[0];
                    let physical_loc = &loc["physicalLocation"];
                    let file_path = physical_loc["artifactLocation"]["uri"].as_str()
                        .or_else(|| physical_loc["artifactLocation"]["uriBaseId"].as_str())
                        .or_else(|| loc["physicalLocation"]["artifactLocation"]["uri"].as_str());
                    let line_num = physical_loc["region"]["startLine"].as_u64()
                        .or_else(|| physical_loc["region"]["startLine"].as_i64().map(|n| n as u64));
                    
                    let location = file_path.map(|f| {
                        if let Some(ln) = line_num {
                            format!("{}:{}", f, ln)
                        } else {
                            f.to_string()
                        }
                    });
                    
                    (location, file_path.map(|s| s.to_string()), line_num.map(|n| n as u32))
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };
            
            let wp = WeakPoint {
                category,
                location: location.clone(),
                file,
                line,
                severity,
                description: message,
                recommended_attack: Vec::new(),
                suppressed: false,
                test_context: None,
            };
            
            weak_points.push(wp);
        }
    }
    
    Ok(weak_points)
}

/// High-level function to scan a workspace and emit cargo-deny weak points
pub fn scan_workspace(
    workspace_root: &Path,
    deny_toml: Option<&Path>,
) -> Result<Vec<WeakPoint>> {
    let config = CargoDenyConfig {
        workspace_root: workspace_root.to_path_buf(),
        deny_toml: deny_toml.map(|p| p.to_path_buf()),
        format: "json".to_string(),
        fail_on_warnings: false,
        extra_args: Vec::new(),
    };
    
    run_cargo_deny(&config)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_mapping() {
        assert_eq!(Severity::from(DenySeverity::Error), Severity::High);
        assert_eq!(Severity::from(DenySeverity::Warning), Severity::Medium);
        assert_eq!(Severity::from(DenySeverity::Note), Severity::Low);
    }
    
    #[test]
    fn test_code_to_category() {
        assert_eq!(code_to_category("RUSTSEC-2021-0001"), WeakPointCategory::Advisory);
        assert_eq!(code_to_category("CVE-2021-12345"), WeakPointCategory::Advisory);
        assert_eq!(code_to_category("banned"), WeakPointCategory::BannedDep);
        assert_eq!(code_to_category("license"), WeakPointCategory::LicensePolicy);
        assert_eq!(code_to_category("unknown-source"), WeakPointCategory::UnknownSource);
    }
    
    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_deny_severity("error"), DenySeverity::Error);
        assert_eq!(parse_deny_severity("ERROR"), DenySeverity::Error);
        assert_eq!(parse_deny_severity("warning"), DenySeverity::Warning);
        assert_eq!(parse_deny_severity("note"), DenySeverity::Note);
        assert_eq!(parse_deny_severity("unknown"), DenySeverity::Note);
    }

    #[test]
    fn test_parse_deny_output_json() {
        let json_output = r#"{
            "diagnostics": [
                {
                    "message": "License MIT not in allow list",
                    "severity": "error",
                    "code": "license",
                    "location": {
                        "file": "Cargo.toml",
                        "line": 15,
                        "column": 1
                    }
                },
                {
                    "message": "Banned dependency: old-crate v1.0.0",
                    "severity": "error",
                    "code": "banned",
                    "location": {
                        "file": "Cargo.toml",
                        "line": 10,
                        "column": 1
                    }
                },
                {
                    "message": "Advisory RUSTSEC-2021-0001 for crate foo",
                    "severity": "warning",
                    "code": "RUSTSEC-2021-0001",
                    "location": {
                        "file": "Cargo.toml",
                        "line": 20
                    }
                }
            ]
        }"#;

        let deny_output: DenyOutput = serde_json::from_str(json_output).unwrap();
        
        // Verify the parsing logic works
        assert_eq!(deny_output.diagnostics.len(), 3);
        assert_eq!(deny_output.diagnostics[0].code, Some("license".to_string()));
        assert_eq!(deny_output.diagnostics[1].code, Some("banned".to_string()));
        assert_eq!(deny_output.diagnostics[2].code, Some("RUSTSEC-2021-0001".to_string()));
    }
}
