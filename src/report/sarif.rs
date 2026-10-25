// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

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
    pub properties: serde_json::Value,
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

/// Map WeakPointCategory to its stable rule ID. Delegates to the single
/// table on the enum (`WeakPointCategory::rule_id`) so SARIF, storage and
/// proof coverage cannot drift apart.
pub(crate) fn rule_id(category: &WeakPointCategory) -> &'static str {
    category.rule_id()
}

/// Map WeakPointCategory to a human-readable name
pub(crate) fn rule_name(category: &WeakPointCategory) -> &'static str {
    match category {
        WeakPointCategory::UncheckedAllocation => "unchecked-allocation",
        WeakPointCategory::UnboundedAllocation => "unbounded-allocation",
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
        WeakPointCategory::CryptoMisuse => "crypto-misuse",
        WeakPointCategory::SupplyChain => "supply-chain",
        WeakPointCategory::InputBoundary => "input-boundary",
        WeakPointCategory::MutationGap => "mutation-gap",
        WeakPointCategory::LicensePolicy => "license-policy",
        WeakPointCategory::Advisory => "advisory",
        WeakPointCategory::BannedDep => "banned-dep",
        WeakPointCategory::UnknownSource => "unknown-source",
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

/// Convert findings to a SARIF 2.1.0 log with coverage in the run's properties.
/// Coverage paths are made relative to the target directory (or the parent
/// of a file target) when that prefix matches; other paths are retained.
///
/// # Errors
/// Propagates errors serialising coverage to a JSON value.
pub fn to_sarif(report: &AssailReport) -> Result<SarifLog> {
    let mut coverage = report.coverage.clone();
    let root = if report.program_path.is_dir() {
        report.program_path.as_path()
    } else {
        report
            .program_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
    };
    for input in &mut coverage.inputs {
        input.path = input
            .path
            .strip_prefix(root)
            .unwrap_or(&input.path)
            .to_path_buf();
    }
    let coverage = serde_json::to_value(&coverage)?;

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
            properties: serde_json::json!({"coverage": coverage}),
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
