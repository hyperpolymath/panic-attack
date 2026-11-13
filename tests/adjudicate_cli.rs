// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! CLI contract for `panic-attack adjudicate`: an adjudication that processed
//! no report, or failed to load any report, must never read as `pass`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn adjudicate(dir: &Path, reports: &[&Path]) -> (Output, serde_json::Value) {
    let out = dir.join("out.json");
    let output = Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .current_dir(dir)
        .arg("adjudicate")
        .args(reports)
        .arg("--output")
        .arg(&out)
        .output()
        .expect("binary should run");
    let json = fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    (output, json)
}

fn good_abduct(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("good-abduct.json");
    let report = serde_json::json!({
        "schema_version": "2.5",
        "created_at": "2026-01-01T00:00:00Z",
        "target": "src/main.rs",
        "source_root": ".",
        "workspace_dir": "runtime/abduct",
        "dependency_scope": "none",
        "selected_files": 0,
        "locked_files": 0,
        "mtime_shifted_files": 0,
        "mtime_offset_days": 0,
        "time_mode": "normal",
        "time_scale": null,
        "virtual_now": null,
        "files": [],
        "execution": null,
    });
    fs::write(&p, report.to_string()).unwrap();
    p
}

#[test]
fn missing_file_is_not_pass() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nope.json");
    let (o, j) = adjudicate(dir.path(), &[&missing]);
    assert_eq!(o.status.code(), Some(2), "{:?}", o);
    assert_eq!(j["verdict"], "error");
    assert_eq!(j["processed_reports"], 0);
    assert_eq!(j["failed_reports"], 1);
    assert!(j["notes"].to_string().contains("nope.json"));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("verdict: pass"));
}

#[test]
fn unrecognised_file_is_not_pass() {
    let dir = TempDir::new().unwrap();
    let junk = dir.path().join("junk.json");
    fs::write(&junk, r#"{"hello": "world"}"#).unwrap();
    let (o, j) = adjudicate(dir.path(), &[&junk]);
    assert_eq!(o.status.code(), Some(2), "{:?}", o);
    assert_eq!(j["verdict"], "error");
    assert_eq!(j["failed_reports"], 1);
    assert!(String::from_utf8_lossy(&o.stderr).contains("junk.json"));
}

#[test]
fn good_plus_bad_is_not_pass() {
    let dir = TempDir::new().unwrap();
    let good = good_abduct(dir.path());
    let missing = dir.path().join("gone.json");

    // Control: the good report alone passes and exits 0.
    let (o, j) = adjudicate(dir.path(), &[&good]);
    assert_eq!(j["processed_reports"], 1, "fixture must parse: {:?}", o);
    assert_eq!(j["verdict"], "pass");
    assert_eq!(o.status.code(), Some(0));

    let (o, j) = adjudicate(dir.path(), &[&good, &missing]);
    assert_eq!(j["processed_reports"], 1);
    assert_eq!(j["failed_reports"], 1);
    assert_eq!(j["verdict"], "error");
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn zero_arguments_is_rejected() {
    let dir = TempDir::new().unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .current_dir(dir.path())
        .arg("adjudicate")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("verdict: pass"));
}
