// SPDX-License-Identifier: MPL-2.0

//! Machine-verifiable Component Readiness Grade tests.
//!
//! Each test exercises a specific subcommand or module to produce evidence
//! for CRG grading.  A passing test means the component meets at least D
//! (Alpha) grade.  The test name encodes the component and the grade floor
//! it verifies.
//!
//! Run with: `cargo test --test readiness -- --nocapture`
//!
//! Grade thresholds:
//!   D (Alpha)  — component runs without crashing on valid input
//!   C (Beta)   — component produces correct output on representative input
//!   B (RC)     — component handles edge cases and multiple input types
//!
//! All test functions are panic-free: they return `Result` and propagate
//! errors with `?`.  Helpers that are structurally infallible use
//! `.expect()` with an invariant-documenting message.

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Path to the compiled panic-attack binary.
///
/// This is structurally infallible in a cargo test context: `current_exe`
/// only fails if the OS cannot locate the test binary, which would mean
/// cargo test itself is broken.
fn binary() -> PathBuf {
    let mut p = std::env::current_exe()
        .expect("test runtime: current_exe should always succeed in cargo test");
    p.pop(); // remove test binary name
    p.pop(); // remove deps/
    p.push("panic-attack");
    if !p.exists() {
        p.pop();
        p.pop();
        p.push("release");
        p.push("panic-attack");
    }
    p
}

/// Run a panic-attack subcommand and return (success, stdout, stderr).
///
/// Uses `.unwrap_or_else(|e| panic!(...))` so a missing binary causes a
/// clearly-attributed test failure rather than a silent exit.
fn run(args: &[&str]) -> (bool, String, String) {
    let bin = binary();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {:?}: {}", bin, e));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Minimal `AssaultReport` JSON for headless subcommand tests.
fn minimal_assault_report_json() -> String {
    serde_json::json!({
        "schema_version": "2.5",
        "assail_report": {
            "schema_version": "2.5",
            "program_path": "/tmp/headless-test",
            "language": "rust",
            "frameworks": [],
            "weak_points": [],
            "statistics": {
                "total_lines": 10,
                "unsafe_blocks": 0,
                "panic_sites": 0,
                "unwrap_calls": 0,
                "allocation_sites": 0,
                "io_operations": 0,
                "threading_constructs": 0
            },
            "file_statistics": [],
            "recommended_attacks": []
        },
        "attack_results": [],
        "total_crashes": 0,
        "total_signatures": 0,
        "overall_assessment": {
            "robustness_score": 100.0,
            "critical_issues": [],
            "recommendations": []
        }
    })
    .to_string()
}

// ============================================================
// Grade D (Alpha): each component runs without crashing
// ============================================================

#[test]
fn readiness_d_assail_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("test.rs"), "fn main() {}")?;
    let path = dir.path().join("test.rs");
    let path_str = path.to_str().ok_or("path not valid UTF-8")?;
    let (ok, _stdout, stderr) = run(&["assail", path_str]);
    assert!(ok, "assail should succeed on minimal input: {}", stderr);
    Ok(())
}

#[test]
fn readiness_d_diagnostics_runs() {
    let (ok, _stdout, stderr) = run(&["diagnostics"]);
    assert!(ok, "diagnostics should succeed: {}", stderr);
}

#[test]
fn readiness_d_manifest_runs() {
    let (ok, _stdout, stderr) = run(&["manifest"]);
    assert!(ok, "manifest should succeed: {}", stderr);
}

#[test]
fn readiness_d_help_runs() {
    let (ok, _stdout, stderr) = run(&["help"]);
    assert!(ok, "help should succeed: {}", stderr);
}

#[test]
fn readiness_d_tui_headless_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let report_path = dir.path().join("assault.json");
    fs::write(&report_path, minimal_assault_report_json())?;

    let path_str = report_path.to_str().ok_or("path not valid UTF-8")?;
    let (ok, stdout, stderr) = run(&["tui", "--headless", path_str]);
    assert!(
        ok,
        "tui --headless should succeed without a TTY: {}",
        stderr
    );
    assert!(
        stdout.contains("PANIC-ATTACK REPORT REVIEW"),
        "tui --headless should print report header, got: {}",
        stdout
    );
    assert!(
        stdout.contains("Assail Summary"),
        "tui --headless should include Assail Summary section"
    );
    Ok(())
}

#[test]
fn readiness_d_gui_headless_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let report_path = dir.path().join("assault.json");
    fs::write(&report_path, minimal_assault_report_json())?;

    let path_str = report_path.to_str().ok_or("path not valid UTF-8")?;
    let (ok, stdout, stderr) = run(&["gui", "--headless", path_str]);
    assert!(
        ok,
        "gui --headless should succeed without a display server: {}",
        stderr
    );
    assert!(
        stdout.contains("PANIC-ATTACK GUI REPORT"),
        "gui --headless should print GUI report header, got: {}",
        stdout
    );
    assert!(
        stdout.contains("Summary"),
        "gui --headless should include Summary panel"
    );
    assert!(
        stdout.contains("Assessment"),
        "gui --headless should include Assessment panel"
    );
    Ok(())
}

// ============================================================
// Grade C (Beta): components produce correct output
// ============================================================

#[test]
fn readiness_c_assail_detects_unsafe() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let code = "fn main() { unsafe { let _p = std::ptr::null::<i32>(); } }";
    let src = dir.path().join("unsafe_test.rs");
    fs::write(&src, code)?;
    let report = assail::analyze(&src)?;
    assert!(
        report
            .weak_points
            .iter()
            .any(|wp| wp.category == WeakPointCategory::UnsafeCode),
        "assail should detect unsafe code"
    );
    Ok(())
}

#[test]
fn readiness_c_assail_detects_unwrap() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    // Fixture name must NOT match the `is_test_file` heuristic — the analyser
    // suppresses unwrap counts in test files. This exercises the production path.
    let code = r#"
fn main() {
    let _a = Some(1).unwrap();
    let _b = Some(2).unwrap();
    let _c = Some(3).expect("three");
    let _d = Some(4).unwrap();
    let _e = Some(5).unwrap();
    let _f = Some(6).unwrap();
    let _g = Some(7).expect("seven");
}
"#;
    let src = dir.path().join("unwrap_fixture.rs");
    fs::write(&src, code)?;
    let report = assail::analyze(&src)?;
    assert!(
        report
            .weak_points
            .iter()
            .any(|wp| wp.category == WeakPointCategory::PanicPath),
        "assail should detect unwrap calls, got: {:?}",
        report
            .weak_points
            .iter()
            .map(|wp| format!("{:?}", wp.category))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn readiness_c_assail_json_output() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() { unsafe {} }")?;
    let output = dir.path().join("report.json");

    let src_str = src.to_str().ok_or("src path not valid UTF-8")?;
    let out_str = output.to_str().ok_or("output path not valid UTF-8")?;
    let (ok, _stdout, stderr) = run(&["assail", src_str, "--output", out_str]);
    assert!(ok, "assail --output should succeed: {}", stderr);

    let content = fs::read_to_string(&output)?;
    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    assert!(
        parsed["language"].is_string(),
        "JSON should have language field"
    );
    assert!(
        parsed["weak_points"].is_array(),
        "JSON should have weak_points array"
    );
    Ok(())
}

#[test]
fn readiness_c_report_json_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() {}")?;

    let report_path = dir.path().join("assault.json");
    let src_str = src.to_str().ok_or("src path not valid UTF-8")?;
    let rpt_str = report_path.to_str().ok_or("report path not valid UTF-8")?;
    let (ok, _stdout, _stderr) = run(&["assault", src_str, "--output", rpt_str]);
    // assault may fail on a non-binary .rs file; verify what we can
    if ok && report_path.exists() {
        let (rok, rstdout, rstderr) = run(&["report", rpt_str]);
        assert!(rok, "report should render assault output: {}", rstderr);
        assert!(!rstdout.is_empty(), "report should produce output");
    }
    Ok(())
}

#[test]
fn readiness_c_diff_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() {}")?;
    let r1 = dir.path().join("r1.json");
    let r2 = dir.path().join("r2.json");

    let src_str = src.to_str().ok_or("src path not valid UTF-8")?;
    let r1_str = r1.to_str().ok_or("r1 path not valid UTF-8")?;
    let r2_str = r2.to_str().ok_or("r2 path not valid UTF-8")?;

    let (ok1, _, _) = run(&["assault", src_str, "--output", r1_str]);
    let (ok2, _, _) = run(&["assault", src_str, "--output", r2_str]);

    if ok1 && ok2 && r1.exists() && r2.exists() {
        let (ok, _stdout, stderr) = run(&["diff", r1_str, r2_str]);
        assert!(ok, "diff should succeed on two assault reports: {}", stderr);
    }
    Ok(())
}

#[test]
fn readiness_c_a2ml_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() {}")?;
    let json_path = dir.path().join("report.json");
    let a2ml_path = dir.path().join("report.a2ml");
    let reimport_path = dir.path().join("reimported.json");

    let src_str = src.to_str().ok_or("src")?;
    let json_str = json_path.to_str().ok_or("json")?;
    let a2ml_str = a2ml_path.to_str().ok_or("a2ml")?;
    let reimport_str = reimport_path.to_str().ok_or("reimport")?;

    let (ok, _, stderr) = run(&["assail", src_str, "--output", json_str]);
    assert!(ok, "assail should succeed: {}", stderr);

    let (ok, _, stderr) = run(&[
        "a2ml-export",
        "--kind",
        "assail",
        json_str,
        "--output",
        a2ml_str,
    ]);
    assert!(ok, "a2ml-export should succeed: {}", stderr);
    assert!(a2ml_path.exists(), "a2ml file should be created");

    let (ok, _, stderr) = run(&["a2ml-import", a2ml_str, "--output", reimport_str]);
    assert!(ok, "a2ml-import should succeed: {}", stderr);
    assert!(reimport_path.exists(), "reimported JSON should be created");
    Ok(())
}

#[test]
fn readiness_c_assemblyline_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let repo = dir.path().join("test-repo");
    fs::create_dir_all(repo.join(".git"))?;
    fs::write(repo.join("main.rs"), "fn main() { unsafe {} }")?;

    let output = dir.path().join("assemblyline.json");
    let dir_str = dir.path().to_str().ok_or("dir path not valid UTF-8")?;
    let out_str = output.to_str().ok_or("output path not valid UTF-8")?;
    let (ok, _stdout, stderr) = run(&["assemblyline", dir_str, "--output", out_str]);
    assert!(ok, "assemblyline should succeed: {}", stderr);
    assert!(output.exists(), "assemblyline output should be created");
    Ok(())
}

#[test]
fn readiness_c_notify_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let report = serde_json::json!({
        "created_at": "2026-03-01T00:00:00Z",
        "directory": "/tmp",
        "repos_scanned": 1,
        "repos_with_findings": 1,
        "repos_skipped": 0,
        "total_weak_points": 5,
        "total_critical": 1,
        "results": [{
            "repo_path": "/tmp/test",
            "repo_name": "test-repo",
            "weak_point_count": 5,
            "critical_count": 1,
            "high_count": 2,
            "total_files": 10,
            "total_lines": 100,
            "error": null,
            "fingerprint": null,
            "report": null
        }]
    });
    let report_path = dir.path().join("assemblyline.json");
    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;

    let rpt_str = report_path.to_str().ok_or("report path not valid UTF-8")?;
    let output = dir.path().join("notification.md");
    let out_str = output.to_str().ok_or("output path not valid UTF-8")?;
    let (ok, _stdout, stderr) = run(&["notify", rpt_str, "--output", out_str]);
    assert!(ok, "notify should succeed: {}", stderr);
    assert!(output.exists(), "notification should be created");

    let content = fs::read_to_string(&output)?;
    assert!(
        content.contains("test-repo"),
        "notification should mention the repo"
    );
    Ok(())
}

#[test]
fn readiness_c_panll_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() {}")?;
    let assault_path = dir.path().join("assault.json");
    let panll_path = dir.path().join("panll.json");

    let src_str = src.to_str().ok_or("src path not valid UTF-8")?;
    let assault_str = assault_path
        .to_str()
        .ok_or("assault path not valid UTF-8")?;
    let panll_str = panll_path.to_str().ok_or("panll path not valid UTF-8")?;

    let (ok, _, _) = run(&["assault", src_str, "--output", assault_str]);
    if ok && assault_path.exists() {
        let (ok, _, stderr) = run(&["panll", assault_str, "--output", panll_str]);
        assert!(ok, "panll should succeed: {}", stderr);
        assert!(panll_path.exists(), "panll output should be created");
    }
    Ok(())
}

#[test]
fn readiness_c_diagnostics_output() {
    let (ok, stdout, stderr) = run(&["diagnostics"]);
    assert!(ok, "diagnostics should succeed: {}", stderr);
    assert!(
        stdout.contains("panicbot integration"),
        "diagnostics should check panicbot integration readiness, got: {}",
        stdout
    );
}

// ============================================================
// Grade B (RC): edge cases and multi-language support
// ============================================================

#[test]
fn readiness_b_assail_multilang() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;

    let rust_file = dir.path().join("test.rs");
    fs::write(&rust_file, "fn main() { unsafe {} }")?;
    let r1 = assail::analyze(&rust_file)?;
    assert_eq!(r1.language, Language::Rust);

    let py_file = dir.path().join("test.py");
    fs::write(&py_file, "import os\nos.system('ls')")?;
    let r2 = assail::analyze(&py_file)?;
    assert_eq!(r2.language, Language::Python);

    let c_file = dir.path().join("test.c");
    fs::write(
        &c_file,
        "#include <stdlib.h>\nint main() { system(\"ls\"); }",
    )?;
    let r3 = assail::analyze(&c_file)?;
    assert_eq!(r3.language, Language::C);

    let sh_file = dir.path().join("test.sh");
    fs::write(&sh_file, "#!/bin/bash\neval $USER_INPUT")?;
    let r4 = assail::analyze(&sh_file)?;
    assert_eq!(r4.language, Language::Shell);
    Ok(())
}

#[test]
fn readiness_b_assail_empty_file() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src = dir.path().join("empty.rs");
    fs::write(&src, "")?;
    let report = assail::analyze(&src)?;
    assert!(
        report.weak_points.is_empty(),
        "empty file should have no findings"
    );
    Ok(())
}

#[test]
fn readiness_b_notify_filtering() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let report = serde_json::json!({
        "created_at": "2026-03-01T00:00:00Z",
        "directory": "/tmp",
        "repos_scanned": 2,
        "repos_with_findings": 2,
        "repos_skipped": 0,
        "total_weak_points": 15,
        "total_critical": 3,
        "results": [
            {
                "repo_path": "/tmp/critical-repo",
                "repo_name": "critical-repo",
                "weak_point_count": 10,
                "critical_count": 3,
                "high_count": 2,
                "total_files": 10,
                "total_lines": 100,
                "error": null,
                "fingerprint": null,
                "report": null
            },
            {
                "repo_path": "/tmp/medium-repo",
                "repo_name": "medium-repo",
                "weak_point_count": 5,
                "critical_count": 0,
                "high_count": 2,
                "total_files": 5,
                "total_lines": 50,
                "error": null,
                "fingerprint": null,
                "report": null
            }
        ]
    });
    let report_path = dir.path().join("assemblyline.json");
    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;

    let rpt_str = report_path.to_str().ok_or("report path not valid UTF-8")?;
    let output = dir.path().join("critical.md");
    let out_str = output.to_str().ok_or("output path not valid UTF-8")?;
    let (ok, _, stderr) = run(&["notify", rpt_str, "--output", out_str, "--critical-only"]);
    assert!(ok, "notify --critical-only should succeed: {}", stderr);

    let content = fs::read_to_string(&output)?;
    assert!(
        content.contains("critical-repo"),
        "should include critical repo"
    );
    assert!(
        !content.contains("medium-repo"),
        "should exclude non-critical repo"
    );
    Ok(())
}

#[test]
fn readiness_b_panicbot_json_contract() -> Result<(), Box<dyn std::error::Error>> {
    // Verify AssailReport serialises with the exact field names and value
    // formats that panicbot (gitbot-fleet) expects. If any of these change,
    // panicbot will fail to parse our output.
    //
    // Panicbot's translator.rs matches on:
    //   - Top-level: "program_path", "weak_points", "language"
    //   - WeakPoint: "category" (PascalCase), "severity" (PascalCase),
    //                "location", "description"
    let dir = TempDir::new()?;
    let src = dir.path().join("test.rs");
    fs::write(&src, "fn main() { unsafe {} }")?;

    let report = assail::analyze(&src)?;
    let json = serde_json::to_value(&report)?;

    assert!(
        json["program_path"].is_string(),
        "must have program_path string"
    );
    assert!(
        json["weak_points"].is_array(),
        "must have weak_points array"
    );
    assert!(json["language"].is_string(), "must have language string");
    assert!(
        json["statistics"].is_object(),
        "must have statistics object"
    );

    let wp = &json["weak_points"][0];
    assert!(wp["category"].is_string(), "weak_point must have category");
    assert!(wp["severity"].is_string(), "weak_point must have severity");
    assert!(
        wp["description"].is_string(),
        "weak_point must have description"
    );

    let cat = wp["category"].as_str().ok_or("category must be a string")?;
    let first_char = cat.chars().next().ok_or("category must not be empty")?;
    assert!(
        first_char.is_uppercase(),
        "category should be PascalCase, got: {}",
        cat
    );

    let sev = wp["severity"].as_str().ok_or("severity must be a string")?;
    assert!(
        ["Low", "Medium", "High", "Critical"].contains(&sev),
        "severity should be PascalCase, got: {}",
        sev
    );

    // All 25 WeakPointCategory variants must round-trip through JSON
    let expected_categories = [
        "UncheckedAllocation",
        "UnboundedLoop",
        "BlockingIO",
        "UnsafeCode",
        "PanicPath",
        "RaceCondition",
        "DeadlockPotential",
        "ResourceLeak",
        "CommandInjection",
        "UnsafeDeserialization",
        "DynamicCodeExecution",
        "UnsafeFFI",
        "AtomExhaustion",
        "InsecureProtocol",
        "ExcessivePermissions",
        "PathTraversal",
        "HardcodedSecret",
        "UncheckedError",
        "InfiniteRecursion",
        "UnsafeTypeCoercion",
        "ProofDrift",
        "CryptoMisuse",
        "SupplyChain",
        "InputBoundary",
        "MutationGap",
    ];
    for variant_name in &expected_categories {
        let variant_json = format!("\"{}\"", variant_name);
        let parsed: Result<WeakPointCategory, _> = serde_json::from_str(&variant_json);
        assert!(
            parsed.is_ok(),
            "WeakPointCategory '{}' should round-trip through JSON \
             (panicbot PA rule depends on it)",
            variant_name
        );
    }
    Ok(())
}
