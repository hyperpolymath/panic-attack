// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
use panic_attack::assail;
use std::process::Command;

#[test]
fn coverage_is_not_the_finding_statistics_array() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("clean.php"),
        "<?php function f() { return 1; }",
    )
    .unwrap();
    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.schema_version, "2.6");
    assert_eq!(report.coverage.status, "complete");
    assert_eq!(report.coverage.analyzed_files, 1);
    assert_eq!(report.coverage.candidate_files, 1);
    assert!(report.file_statistics.is_empty()); // no counters != no analysis
    assert!(report.coverage.inputs[0].content_blake3.is_some());
}

#[test]
fn malformed_php_and_unsupported_inputs_are_visible() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("stub.php"),
        "<?php function encrypt($x) { /* TODO */ }",
    )
    .unwrap();
    std::fs::write(dir.path().join("bad.php"), "<?php function broken( {").unwrap();
    std::fs::write(dir.path().join("config.toml"), "enabled = true\n").unwrap();
    std::fs::write(dir.path().join("README.md"), "Documentation").unwrap();
    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.coverage.status, "partial");
    assert_eq!(report.coverage.candidate_files, 3);
    assert_eq!(report.coverage.analyzed_files, 1);
    assert_eq!(report.coverage.inputs.len(), 4);
    assert!(report
        .coverage
        .inputs
        .iter()
        .any(|i| i.status == "parse_error"));
    assert!(report
        .coverage
        .inputs
        .iter()
        .any(|i| i.status == "unsupported"));
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.description.starts_with("PHP-EMPTY-CALLABLE:")));
}

#[test]
fn headless_output_is_json_and_strict_gate_preserves_the_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.php"), "<?php function broken( {").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .args([
            "assail",
            dir.path().to_str().unwrap(),
            "--headless",
            "--fail-on-incomplete",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage"]["status"], "failed");
    assert_eq!(report["coverage"]["mode"], "static_assail");
}

#[test]
fn empty_scan_has_explicit_status_and_strict_failure() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .args([
            "assail",
            dir.path().to_str().unwrap(),
            "--headless",
            "--fail-on-incomplete",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage"]["status"], "no_applicable_input");
}

#[cfg(unix)]
#[test]
fn symlink_cycles_are_excluded_instead_of_followed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("clean.php"), "<?php echo 'ok';").unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("cycle")).unwrap();
    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.coverage.analyzed_files, 1);
    assert!(report
        .coverage
        .inputs
        .iter()
        .any(|i| i.kind == "non_regular" && i.status == "excluded"));
}

#[test]
fn legacy_json_does_not_gain_invented_coverage() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("clean.php"), "<?php echo 'ok';").unwrap();
    let mut value = serde_json::to_value(assail::analyze(dir.path()).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("coverage");
    let legacy: panic_attack::types::AssailReport = serde_json::from_value(value).unwrap();
    assert_eq!(legacy.coverage.status, "unknown");
    assert!(legacy.coverage.incomplete());
}

#[test]
fn describe_contract_advertises_the_assail_schema_and_coverage_gate() {
    let output = Command::new(env!("CARGO_BIN_EXE_panic-attack"))
        .arg("describe-contract")
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report_schema_versions"]["assail"], "2.6");
    assert_eq!(json["report_schema_versions"]["assault"], "2.5");
    assert!(json["modes"]["assail"]["flags"]
        .to_string()
        .contains("fail_on_incomplete"));
}

#[test]
fn oversize_source_is_not_reported_as_analyzed() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("large.php")).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.coverage.analyzed_files, 0);
    assert!(report.coverage.inputs[0]
        .reason
        .as_ref()
        .unwrap()
        .contains("16 MiB"));
    assert!(report.coverage.incomplete());
}
