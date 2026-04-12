// SPDX-License-Identifier: PMPL-1.0-or-later

//! SARIF 2.1.0 output for GitHub Security tab integration
//!
//! Converts AssailReport weak points into OASIS SARIF format.
//! See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::types::{AssailReport, Severity, WeakPointCategory};
use anyhow::Result;
use serde::Serialize;

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Top-level SARIF log
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run (one tool execution)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// Tool descriptor
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifToolComponent,
}

/// Tool component with rules
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifToolComponent {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// Rule descriptor
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub default_configuration: SarifConfiguration,
}

/// Configuration with level
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifConfiguration {
    pub level: String,
}

/// A single finding
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

/// Message with text
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

/// Physical location
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

/// Physical location with artifact
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// Artifact URI
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// Region (line number)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: u32,
}

/// Map WeakPointCategory to a stable rule ID
fn rule_id(category: &WeakPointCategory) -> &'static str {
    match category {
        WeakPointCategory::UncheckedAllocation => "PA001",
        WeakPointCategory::UnboundedLoop => "PA002",
        WeakPointCategory::BlockingIO => "PA003",
        WeakPointCategory::UnsafeCode => "PA004",
        WeakPointCategory::PanicPath => "PA005",
        WeakPointCategory::RaceCondition => "PA006",
        WeakPointCategory::DeadlockPotential => "PA007",
        WeakPointCategory::ResourceLeak => "PA008",
        WeakPointCategory::CommandInjection => "PA009",
        WeakPointCategory::UnsafeDeserialization => "PA010",
        WeakPointCategory::DynamicCodeExecution => "PA011",
        WeakPointCategory::UnsafeFFI => "PA012",
        WeakPointCategory::AtomExhaustion => "PA013",
        WeakPointCategory::InsecureProtocol => "PA014",
        WeakPointCategory::ExcessivePermissions => "PA015",
        WeakPointCategory::PathTraversal => "PA016",
        WeakPointCategory::HardcodedSecret => "PA017",
        WeakPointCategory::UncheckedError => "PA018",
        WeakPointCategory::InfiniteRecursion => "PA019",
        WeakPointCategory::UnsafeTypeCoercion => "PA020",
        WeakPointCategory::ProofDrift => "PA021",
    }
}

/// Map WeakPointCategory to a human-readable name
fn rule_name(category: &WeakPointCategory) -> &'static str {
    match category {
        WeakPointCategory::UncheckedAllocation => "unchecked-allocation",
        WeakPointCategory::UnboundedLoop => "unbounded-loop",
        WeakPointCategory::BlockingIO => "blocking-io",
        WeakPointCategory::UnsafeCode => "unsafe-code",
        WeakPointCategory::PanicPath => "panic-path",
        WeakPointCategory::RaceCondition => "race-condition",
        WeakPointCategory::DeadlockPotential => "deadlock-potential",
        WeakPointCategory::ResourceLeak => "resource-leak",
        WeakPointCategory::CommandInjection => "command-injection",
        WeakPointCategory::UnsafeDeserialization => "unsafe-deserialization",
        WeakPointCategory::DynamicCodeExecution => "dynamic-code-execution",
        WeakPointCategory::UnsafeFFI => "unsafe-ffi",
        WeakPointCategory::AtomExhaustion => "atom-exhaustion",
        WeakPointCategory::InsecureProtocol => "insecure-protocol",
        WeakPointCategory::ExcessivePermissions => "excessive-permissions",
        WeakPointCategory::PathTraversal => "path-traversal",
        WeakPointCategory::HardcodedSecret => "hardcoded-secret",
        WeakPointCategory::UncheckedError => "unchecked-error",
        WeakPointCategory::InfiniteRecursion => "infinite-recursion",
        WeakPointCategory::UnsafeTypeCoercion => "unsafe-type-coercion",
        WeakPointCategory::ProofDrift => "proof-drift",
    }
}

/// Map Severity to SARIF level
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Parse a location string like "src/main.rs:42" into (path, optional line)
fn parse_location(loc: &str) -> (&str, Option<u32>) {
    if let Some(colon_pos) = loc.rfind(':') {
        let (path, rest) = loc.split_at(colon_pos);
        if let Ok(line) = rest[1..].parse::<u32>() {
            return (path, Some(line));
        }
    }
    (loc, None)
}

/// Convert an AssailReport to SARIF JSON
pub fn to_sarif(report: &AssailReport) -> Result<SarifLog> {
    // Collect unique rules
    let mut seen_categories = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for wp in &report.weak_points {
        if seen_categories.insert(wp.category) {
            rules.push(SarifRule {
                id: rule_id(&wp.category).to_string(),
                name: rule_name(&wp.category).to_string(),
                short_description: SarifMessage {
                    text: format!("{:?}", wp.category),
                },
                default_configuration: SarifConfiguration {
                    level: sarif_level(&wp.severity).to_string(),
                },
            });
        }
    }

    // Convert weak points to results
    let results: Vec<SarifResult> = report
        .weak_points
        .iter()
        .map(|wp| {
            let loc_str = wp.location.as_deref().unwrap_or("unknown");
            let (path, line) = parse_location(loc_str);

            SarifResult {
                rule_id: rule_id(&wp.category).to_string(),
                level: sarif_level(&wp.severity).to_string(),
                message: SarifMessage {
                    text: wp.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: path.to_string(),
                        },
                        region: line.map(|l| SarifRegion { start_line: l }),
                    },
                }],
            }
        })
        .collect();

    Ok(SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "panic-attack".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/hyperpolymath/panic-attacker".to_string(),
                    rules,
                },
            },
            results,
        }],
    })
}

/// Serialize a SARIF log to JSON string
pub fn to_sarif_json(report: &AssailReport) -> Result<String> {
    let log = to_sarif(report)?;
    let json = serde_json::to_string_pretty(&log)?;
    Ok(json)
}
