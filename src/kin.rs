// SPDX-License-Identifier: PMPL-1.0-or-later

//! Kin Protocol — heartbeat reporting for ecosystem coordination.
//!
//! panic-attacker reports its health to `~/.hypatia/kin/panic-attacker.heartbeat.json`
//! after every run. Hypatia's Kin.Coordinator reads these heartbeats to maintain
//! awareness of the entire ecosystem.

use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

const KIN_DIR: &str = ".hypatia/kin";
const KIN_ID: &str = "panic-attacker";

#[derive(Serialize)]
pub struct Heartbeat {
    pub kin_id: &'static str,
    pub role: &'static str,
    pub timestamp: String,
    pub status: HeartbeatStatus,
    pub version: &'static str,
    pub last_run: Option<RunMetrics>,
    pub errors: Vec<String>,
    pub capabilities: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HeartbeatStatus {
    Healthy,
    Degraded,
    Error,
}

#[derive(Serialize)]
pub struct RunMetrics {
    pub command: String,
    pub repos_scanned: Option<usize>,
    pub findings: Option<usize>,
    pub duration_secs: Option<f64>,
    pub exit_success: bool,
}

fn kin_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(KIN_DIR)
}

fn heartbeat_path() -> PathBuf {
    kin_dir().join(format!("{}.heartbeat.json", KIN_ID))
}

/// Write a heartbeat after a successful run.
pub fn write_heartbeat(metrics: RunMetrics, errors: Vec<String>) -> Result<()> {
    let dir = kin_dir();
    fs::create_dir_all(&dir)?;

    let status = if errors.is_empty() {
        HeartbeatStatus::Healthy
    } else {
        HeartbeatStatus::Degraded
    };

    let heartbeat = Heartbeat {
        kin_id: KIN_ID,
        role: "scanner",
        timestamp: iso8601_now(),
        status,
        version: env!("CARGO_PKG_VERSION"),
        last_run: Some(metrics),
        errors,
        capabilities: vec!["scan", "assail", "assemblyline", "sarif", "kanren", "attestation"],
    };

    let json = serde_json::to_string_pretty(&heartbeat)?;
    fs::write(heartbeat_path(), format!("{}\n", json))?;
    Ok(())
}

/// Write a minimal heartbeat on startup (before any scan runs).
pub fn write_startup_heartbeat() -> Result<()> {
    let dir = kin_dir();
    fs::create_dir_all(&dir)?;

    let heartbeat = Heartbeat {
        kin_id: KIN_ID,
        role: "scanner",
        timestamp: iso8601_now(),
        status: HeartbeatStatus::Healthy,
        version: env!("CARGO_PKG_VERSION"),
        last_run: None,
        errors: vec![],
        capabilities: vec!["scan", "assail", "assemblyline", "sarif", "kanren", "attestation"],
    };

    let json = serde_json::to_string_pretty(&heartbeat)?;
    fs::write(heartbeat_path(), format!("{}\n", json))?;
    Ok(())
}

/// Write an error heartbeat when something goes wrong.
pub fn write_error_heartbeat(error_msg: String) -> Result<()> {
    let dir = kin_dir();
    fs::create_dir_all(&dir)?;

    let heartbeat = Heartbeat {
        kin_id: KIN_ID,
        role: "scanner",
        timestamp: iso8601_now(),
        status: HeartbeatStatus::Error,
        version: env!("CARGO_PKG_VERSION"),
        last_run: None,
        errors: vec![error_msg],
        capabilities: vec!["scan", "assail", "assemblyline", "sarif", "kanren", "attestation"],
    };

    let json = serde_json::to_string_pretty(&heartbeat)?;
    fs::write(heartbeat_path(), format!("{}\n", json))?;
    Ok(())
}

fn iso8601_now() -> String {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple UTC timestamp without pulling in chrono
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Days since Unix epoch to Y-M-D (simplified)
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
