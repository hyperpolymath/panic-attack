// SPDX-License-Identifier: PMPL-1.0-or-later

//! Persistent storage helpers for assault reports
//!
//! Two storage modes:
//! - **Filesystem**: Writes reports to timestamped files in a local directory.
//!   Supports multiple output formats (JSON, YAML, Nickel, SARIF).
//! - **VerisimDb**: Wraps reports in VerisimDB hexad format and writes them
//!   to a local directory structure matching the planned VerisimDB API layout.
//!   Currently file-based only — HTTP API integration is planned for when
//!   VerisimDB's REST endpoint stabilises.
//!
//! Both modes create parent directories as needed and return the paths of
//! all files written.

use crate::report::ReportOutputFormat;
use crate::types::AssaultReport;
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// Direct filesystem persistence in the chosen output format(s)
    Filesystem,
    /// VerisimDB hexad format (file-based; HTTP API planned)
    VerisimDb,
}

impl StorageMode {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "filesystem" | "disk" | "local" => Some(StorageMode::Filesystem),
            "verisimdb" | "verisim" | "veri" => Some(StorageMode::VerisimDb),
            _ => None,
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
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
        let hexad_dir = base_dir.join("hexads");
        fs::create_dir_all(&hexad_dir)?;

        let hexad = build_hexad(report)?;
        let path = hexad_dir.join(format!("{}.json", hexad.id));
        let payload = serde_json::to_string_pretty(&hexad)?;
        fs::write(&path, payload)?;
        stored.push(path);
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
            high_count: report
                .results
                .iter()
                .map(|r| r.high_count)
                .sum(),
            total_crashes: 0,
            robustness_score: 0.0,
            categories,
            migration: None,
        },
        document,
    })
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
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
        let hexad_dir = base_dir.join("hexads");
        fs::create_dir_all(&hexad_dir)?;

        let hexad = build_assemblyline_hexad(report)?;
        let path = hexad_dir.join(format!("{}.json", hexad.id));
        let payload = serde_json::to_string_pretty(&hexad)?;
        fs::write(&path, payload)?;
        stored.push(path);
    }

    Ok(stored)
}

// ---------------------------------------------------------------------------
// VeriSimDB HTTP API integration (via V-lang gateway on port 9090)
// ---------------------------------------------------------------------------

/// Push a hexad to the VeriSimDB V-lang API gateway via REST.
///
/// Endpoint: POST http://{host}:{port}/api/v1/hexads
/// The V-lang gateway proxies to the Rust core on port 8080.
///
/// Requires the `http` feature flag: `cargo build --features http`
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_http(hexad: &PanicAttackHexad, gateway_url: &str) -> Result<String> {
    let url = format!("{}/api/v1/hexads", gateway_url.trim_end_matches('/'));
    let payload = serde_json::to_string(hexad)?;

    let response = attach_auth(ureq::post(&url))
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| anyhow!("VeriSimDB gateway error: {}", e))?;

    let status = response.status();
    let body = response
        .into_string()
        .unwrap_or_else(|_| String::from("(no body)"));

    if status >= 200 && status < 300 {
        Ok(body)
    } else {
        Err(anyhow!(
            "VeriSimDB gateway returned {}: {}",
            status,
            body
        ))
    }
}

/// Push a hexad via HTTP, falling back to filesystem if the gateway is unavailable.
///
/// Uses VERISIM_GATEWAY_URL env var (default: http://localhost:9090).
/// Checks gateway health (cached for 30s) before attempting HTTP push.
/// Retries with exponential backoff (3 attempts: 1s, 2s, 4s) before falling back.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_with_fallback(
    hexad: &PanicAttackHexad,
    fallback_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let gateway_url = std::env::var("VERISIM_GATEWAY_URL")
        .unwrap_or_else(|_| "http://localhost:9090".to_string());

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
fn fallback_write_hexad(
    hexad: &PanicAttackHexad,
    fallback_dir: &Path,
) -> Result<Vec<PathBuf>> {
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
// ---------------------------------------------------------------------------

/// Cached gateway health state: stores (is_healthy, timestamp_secs).
/// Used to avoid repeated HTTP attempts against a known-down gateway.
#[cfg(feature = "http")]
static GATEWAY_HEALTH: std::sync::OnceLock<std::sync::Mutex<(bool, u64)>> =
    std::sync::OnceLock::new();

/// Duration (in seconds) to cache a gateway health check result.
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

/// Build a ureq::Request with optional Bearer token from `VERISIM_API_TOKEN`.
///
/// If the environment variable is set and non-empty the `Authorization` header
/// is attached; otherwise the request is sent unauthenticated.
#[cfg(feature = "http")]
fn attach_auth(request: ureq::Request) -> ureq::Request {
    match std::env::var("VERISIM_API_TOKEN") {
        Ok(token) if !token.is_empty() => {
            request.set("Authorization", &format!("Bearer {}", token))
        }
        _ => request,
    }
}

/// Push a single hexad with exponential-backoff retry.
///
/// Makes up to 3 attempts with delays of 1 s, 2 s, 4 s between them.
/// Returns as soon as one attempt succeeds.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexad_http_with_retry(
    hexad: &PanicAttackHexad,
    gateway_url: &str,
) -> Result<String> {
    let delays = [
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(4),
    ];
    let max_attempts: usize = 3;
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..max_attempts {
        match push_hexad_http(hexad, gateway_url) {
            Ok(body) => return Ok(body),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts - 1 {
                    std::thread::sleep(delays[attempt]);
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("VeriSimDB push failed after {} attempts", max_attempts)))
}

/// Push a batch of hexads to the VeriSimDB batch endpoint.
///
/// Endpoint: POST `{gateway_url}/api/v1/hexads/batch`
///
/// If the batch endpoint returns HTTP 404 (not implemented on the gateway),
/// falls back to pushing each hexad individually via [`push_hexad_http_with_retry`].
/// Auth token from `VERISIM_API_TOKEN` is attached when present.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn push_hexads_batch(
    hexads: &[PanicAttackHexad],
    gateway_url: &str,
) -> Result<Vec<String>> {
    if hexads.is_empty() {
        return Ok(Vec::new());
    }

    let url = format!("{}/api/v1/hexads/batch", gateway_url.trim_end_matches('/'));
    let payload = serde_json::to_string(hexads)?;

    let request = attach_auth(ureq::post(&url))
        .set("Content-Type", "application/json");

    match request.send_string(&payload) {
        Ok(response) => {
            let status = response.status();
            let body = response
                .into_string()
                .unwrap_or_else(|_| String::from("(no body)"));
            if status >= 200 && status < 300 {
                Ok(vec![body])
            } else {
                Err(anyhow!("VeriSimDB batch returned {}: {}", status, body))
            }
        }
        Err(ureq::Error::Status(404, _)) => {
            // Batch endpoint not available — push individually
            let mut results = Vec::with_capacity(hexads.len());
            for hexad in hexads {
                let body = push_hexad_http_with_retry(hexad, gateway_url)?;
                results.push(body);
            }
            Ok(results)
        }
        Err(e) => Err(anyhow!("VeriSimDB batch request failed: {}", e)),
    }
}

/// Query hexads from the VeriSimDB gateway for temporal diff comparison.
///
/// Endpoint: GET `{gateway_url}/api/v1/hexads?tool=panic-attack&limit={limit}`
///
/// Returns parsed hexads from the gateway. Useful for comparing current scan
/// results against previous scans stored in VeriSimDB.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn query_hexads(gateway_url: &str, limit: usize) -> Result<Vec<PanicAttackHexad>> {
    let url = format!(
        "{}/api/v1/hexads?tool=panic-attack&limit={}",
        gateway_url.trim_end_matches('/'),
        limit,
    );

    let request = attach_auth(ureq::get(&url));
    let response = request
        .call()
        .map_err(|e| anyhow!("VeriSimDB query failed: {}", e))?;

    let status = response.status();
    let body = response
        .into_string()
        .unwrap_or_else(|_| String::from("[]"));

    if status >= 200 && status < 300 {
        let hexads: Vec<PanicAttackHexad> = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Failed to parse VeriSimDB response: {}", e))?;
        Ok(hexads)
    } else {
        Err(anyhow!("VeriSimDB query returned {}: {}", status, body))
    }
}

/// Check whether the VeriSimDB gateway is reachable.
///
/// Endpoint: GET `{gateway_url}/api/v1/health`
///
/// Results are cached for 30 seconds via a static `OnceLock<Mutex<...>>` to
/// avoid hammering a down gateway on every push call.  Returns `true` if the
/// gateway responded 2xx within the cache window, `false` otherwise.
#[cfg(feature = "http")]
#[allow(dead_code)]
pub fn check_gateway(gateway_url: &str) -> bool {
    let mutex = GATEWAY_HEALTH.get_or_init(|| std::sync::Mutex::new((false, 0)));
    let now = now_secs();

    // Check cached result
    if let Ok(guard) = mutex.lock() {
        let (healthy, checked_at) = *guard;
        if now.saturating_sub(checked_at) < HEALTH_CACHE_TTL_SECS {
            return healthy;
        }
    }

    // Cache expired or first call — perform live check
    let url = format!("{}/api/v1/health", gateway_url.trim_end_matches('/'));
    let request = attach_auth(ureq::get(&url));
    let is_healthy = match request.call() {
        Ok(resp) => resp.status() >= 200 && resp.status() < 300,
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
        return Err(anyhow!(
            "storage directory not found: {}",
            dir.display()
        ));
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

    #[test]
    fn test_uuid_from_timestamp() {
        let id = uuid_from_timestamp(1709155200000);
        assert!(!id.is_empty());
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_storage_mode_parsing() {
        assert_eq!(
            StorageMode::from_str("filesystem"),
            Some(StorageMode::Filesystem)
        );
        assert_eq!(
            StorageMode::from_str("verisimdb"),
            Some(StorageMode::VerisimDb)
        );
        assert_eq!(StorageMode::from_str("disk"), Some(StorageMode::Filesystem));
        assert_eq!(StorageMode::from_str("bogus"), None);
    }
}
