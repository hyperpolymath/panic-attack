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
