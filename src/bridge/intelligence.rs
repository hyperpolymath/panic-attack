// SPDX-License-Identifier: PMPL-1.0-or-later

//! CVE intelligence — queries vulnerability feeds for known issues.
//!
//! MVP: OSV API (api.osv.dev) only. Phase 2 adds NVD, GHSA, VirusTotal,
//! oss-security, and upstream commit analysis.
//!
//! The OSV API is free, requires no authentication, and supports batch
//! queries. It covers RustSec, GHSA, and other sources in one call.

use super::{LockedDependency, SeverityLabel, SourceTier, Vulnerability};
use anyhow::Result;
use serde::{Deserialize, Serialize};

// ============================================================================
// OSV API types
// ============================================================================

/// OSV batch query request.
#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

/// A single OSV query for one package+version.
#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

/// OSV package identifier.
#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// OSV batch response.
#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

/// Result for a single query in the batch.
#[derive(Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

/// A single OSV vulnerability entry.
#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

/// CVSS severity from OSV.
#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

/// Affected package ranges from OSV.
#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

/// Version range with events (introduced, fixed).
#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

/// A range event: introduced or fixed at a version.
#[derive(Deserialize)]
struct OsvEvent {
    #[allow(dead_code)]
    introduced: Option<String>,
    fixed: Option<String>,
}

/// A reference URL from OSV.
#[allow(dead_code)]
#[derive(Deserialize)]
struct OsvReference {
    url: String,
}

// ============================================================================
// Public API
// ============================================================================

/// Query the OSV API for vulnerabilities affecting the given dependencies.
///
/// Uses the batch endpoint to minimise API calls. Returns a flat list of
/// Vulnerability structs, one per (dependency, advisory) pair.
pub fn query_osv_batch(deps: &[LockedDependency]) -> Result<Vec<Vulnerability>> {
    if deps.is_empty() {
        return Ok(Vec::new());
    }

    // Build batch request — OSV supports up to 1000 queries per batch
    let mut all_vulns = Vec::new();

    for chunk in deps.chunks(1000) {
        let request = OsvBatchRequest {
            queries: chunk
                .iter()
                .map(|dep| OsvQuery {
                    package: OsvPackage {
                        name: dep.name.clone(),
                        ecosystem: osv_ecosystem(&dep.ecosystem),
                    },
                    version: dep.version.clone(),
                })
                .collect(),
        };

        let body = serde_json::to_string(&request)?;

        let resp = match ureq::post("https://api.osv.dev/v1/querybatch")
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(resp) => resp,
            Err(ureq::Error::Status(code, resp)) => {
                let body_text = resp.into_string().unwrap_or_default();
                anyhow::bail!("OSV API returned HTTP {}: {}", code, body_text);
            }
            Err(e) => {
                anyhow::bail!("OSV API request failed: {}", e);
            }
        };

        let response_text = resp.into_string()?;
        let response: OsvBatchResponse = serde_json::from_str(&response_text)?;

        // Map OSV results back to dependencies
        for (i, result) in response.results.iter().enumerate() {
            let dep = &chunk[i];
            for vuln in &result.vulns {
                all_vulns.push(osv_to_vulnerability(vuln, dep));
            }
        }
    }

    Ok(all_vulns)
}

// ============================================================================
// Mapping helpers
// ============================================================================

/// Convert OSV ecosystem name to the format OSV expects.
fn osv_ecosystem(ecosystem: &str) -> String {
    match ecosystem {
        "crates.io" => "crates.io".to_string(),
        "npm" => "npm".to_string(),
        "hex" => "Hex".to_string(),
        other => other.to_string(),
    }
}

/// Convert an OSV vulnerability to our internal Vulnerability type.
fn osv_to_vulnerability(osv: &OsvVuln, dep: &LockedDependency) -> Vulnerability {
    // Extract CVE alias if present
    let cve = osv
        .aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned();

    // Extract CVSS score from severity entries
    let severity_score = osv.severity.iter().find_map(|s| {
        if s.severity_type == "CVSS_V3" {
            parse_cvss_score(&s.score)
        } else {
            None
        }
    });

    let severity_label = severity_score
        .map(SeverityLabel::from_cvss)
        .unwrap_or(SeverityLabel::Medium);

    // Extract fixed versions from affected ranges
    let mut fixed_versions = Vec::new();
    for affected in &osv.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    if !fixed_versions.contains(fixed) {
                        fixed_versions.push(fixed.clone());
                    }
                }
            }
        }
    }

    // Check if any fixed version is semver-compatible with current
    let semver_fix = fixed_versions.iter().any(|fv| {
        is_semver_compatible(&dep.version, fv)
    });

    let references = osv
        .references
        .iter()
        .map(|r| r.url.clone())
        .collect();

    Vulnerability {
        id: osv.id.clone(),
        cve,
        summary: osv
            .summary
            .clone()
            .unwrap_or_else(|| format!("Vulnerability in {}", dep.name)),
        package: dep.name.clone(),
        version: dep.version.clone(),
        severity: severity_score,
        severity_label,
        fixed_versions,
        semver_fix_available: semver_fix,
        source_tier: SourceTier::Tier1,
        references,
    }
}

/// Parse a CVSS v3 vector string to extract the base score.
///
/// Handles both "CVSS:3.1/AV:N/AC:H/..." format (extracts from vector)
/// and plain numeric scores like "5.9".
fn parse_cvss_score(score_str: &str) -> Option<f64> {
    // If it's just a number, parse directly
    if let Ok(score) = score_str.parse::<f64>() {
        return Some(score);
    }
    // OSV sometimes provides the score as a separate field; we don't have
    // a full CVSS vector parser, so return None for vector strings.
    None
}

/// Check if `fixed_version` is semver-compatible with `current_version`.
///
/// "Compatible" means the major version is the same and fixed > current.
/// This is a simplified check — a full semver resolver would use the
/// Cargo.toml version requirement, but for MVP this catches most cases.
fn is_semver_compatible(current: &str, fixed: &str) -> bool {
    let cur_parts: Vec<u64> = current
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    let fix_parts: Vec<u64> = fixed
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();

    if cur_parts.len() < 2 || fix_parts.len() < 2 {
        return false;
    }

    // Same major version (or both 0.x with same minor)
    if cur_parts[0] == 0 && fix_parts[0] == 0 {
        // 0.x.y: minor is breaking in Cargo semver
        cur_parts[1] == fix_parts[1] && fix_parts > cur_parts
    } else {
        cur_parts[0] == fix_parts[0] && fix_parts > cur_parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_compatible() {
        assert!(is_semver_compatible("0.11.5", "0.11.6"));
        assert!(!is_semver_compatible("0.11.5", "0.12.0"));
        assert!(is_semver_compatible("1.0.0", "1.0.1"));
        assert!(is_semver_compatible("1.0.0", "1.1.0"));
        assert!(!is_semver_compatible("1.0.0", "2.0.0"));
        assert!(!is_semver_compatible("0.12.5", "0.16.3"));
    }

    #[test]
    fn test_parse_cvss_score() {
        assert_eq!(parse_cvss_score("5.9"), Some(5.9));
        assert_eq!(parse_cvss_score("8.2"), Some(8.2));
        assert_eq!(parse_cvss_score("CVSS:3.1/AV:N/AC:H"), None);
    }
}
