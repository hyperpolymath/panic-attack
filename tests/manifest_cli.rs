// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! CLI contract for `panic-attack manifest`, `panic-attack diagnostics` and
//! the start-up manifest load. A missing manifest means the built-in defaults,
//! silently. A manifest that exists but does not load is an error (at start-up,
//! a warning), never silently the defaults.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const POINTER_MANIFEST: &str = r#";; SPDX-License-Identifier: MPL-2.0
(repo-deed
  :schema-version "1.0.0"
  (front-doors :machine "example_chora.deed" :human "README.adoc"))
"#;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("binary should run")
}

#[test]
fn manifest_export_fails_on_a_malformed_default_deed() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("0-AI-MANIFEST.deed"),
        "(manifest (project \"x\"))\n",
    )
    .unwrap();
    let out = dir.path().join("out.ncl");
    fs::write(&out, "previous export\n").unwrap();
    let o = run(dir.path(), &["manifest", "-o", out.to_str().unwrap()]);
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("0-AI-MANIFEST.deed"),
        "{o:?}"
    );
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "previous export\n",
        "a failed export must not overwrite the output"
    );
}

#[test]
fn manifest_export_without_a_manifest_uses_the_defaults() {
    let dir = TempDir::new().unwrap();
    let o = run(dir.path(), &["manifest"]);
    assert!(o.status.success(), "{o:?}");
}

#[test]
fn manifest_export_reads_a_valid_pointer_deed() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("0-AI-MANIFEST.deed"), POINTER_MANIFEST).unwrap();
    let o = run(dir.path(), &["manifest"]);
    assert!(o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("example_chora.deed"),
        "{o:?}"
    );
}

#[test]
fn diagnostics_fails_on_a_malformed_default_deed() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("0-AI-MANIFEST.deed"),
        "(manifest (project \"x\"))\n",
    )
    .unwrap();
    let o = run(dir.path(), &["diagnostics"]);
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("reading manifest 0-AI-MANIFEST.deed"),
        "{o:?}"
    );
}

/// stderr of `panic-attack completions bash`, a command that reads no
/// manifest itself, so only the start-up manifest load can speak.
fn startup_stderr(dir: &Path) -> String {
    let o = run(dir, &["completions", "bash"]);
    assert!(o.status.success(), "{o:?}");
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn no_manifest_is_not_a_warning() {
    let dir = TempDir::new().unwrap();
    let stderr = startup_stderr(dir.path());
    assert!(!stderr.contains("failed to read AI manifest"), "{stderr}");
}

#[test]
fn a_valid_pointer_deed_is_not_a_warning() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("0-AI-MANIFEST.deed"), POINTER_MANIFEST).unwrap();
    let stderr = startup_stderr(dir.path());
    assert!(!stderr.contains("failed to read AI manifest"), "{stderr}");
}

#[test]
fn a_malformed_manifest_still_warns() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("0-AI-MANIFEST.deed"),
        "(manifest (project \"x\"))\n",
    )
    .unwrap();
    let stderr = startup_stderr(dir.path());
    assert!(
        stderr.contains("failed to read AI manifest") && stderr.contains("0-AI-MANIFEST.deed"),
        "{stderr}"
    );
}
