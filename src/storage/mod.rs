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
        let hexad = build_assemblyline_hexad(report)?;

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
}
