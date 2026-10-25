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

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_input_paths_serialize_without_losing_index_lookups() {
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"invalid-\xff.php".to_vec()));
    let content = b"<?php echo 'ok';";
    std::fs::write(&path, content).unwrap();
    let mut report = assail::analyze(dir.path()).unwrap();
    // The extension is valid ASCII even though the stem is not, so this file is
    // analysable and must not be filed away as unsupported/excluded.
    assert_eq!(report.coverage.analyzed_files, 1);
    assert_eq!(report.coverage.inputs[0].status, "analyzed");
    assert_eq!(report.coverage.inputs[0].path, path);
    assert_eq!(report.language, panic_attack::types::Language::Php);
    let single_file_report = assail::analyze(&path).unwrap();
    assert_eq!(
        single_file_report.language,
        panic_attack::types::Language::Php
    );
    assert_eq!(single_file_report.coverage.analyzed_files, 1);
    report
        .coverage
        .mark(&path, "unsupported", None, Some(content));
    assert_eq!(
        report.coverage.inputs[0].content_blake3.as_deref(),
        Some(blake3::hash(content).to_hex().as_str())
    );

    let json = panic_attack::json::to_canonical_string(&report).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["coverage"]["inputs"][0]["path"],
        path.to_string_lossy().as_ref()
    );
    assert_eq!(report.coverage.inputs[0].path, path);
}

#[cfg(target_os = "linux")]
#[test]
fn colliding_lossy_paths_round_trip_with_distinct_bytes() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<_> = [
        b"invalid-\xfe.php".as_slice(),
        b"invalid-\xff.php".as_slice(),
        "invalid-\u{fffd}.php".as_bytes(),
    ]
    .into_iter()
    .map(|name| dir.path().join(std::ffi::OsString::from_vec(name.to_vec())))
    .collect();
    for path in &paths {
        std::fs::write(path, "<?php echo 'ok';").unwrap();
        assert_eq!(path.to_string_lossy(), paths[0].to_string_lossy());
    }

    let report = assail::analyze(dir.path()).unwrap();
    assert_eq!(report.coverage.analyzed_files, 3);
    let json = panic_attack::json::to_canonical_string(&report).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    for input in value["coverage"]["inputs"].as_array().unwrap() {
        assert_eq!(input["path"], paths[0].to_string_lossy().as_ref());
    }
    let mut restored: panic_attack::types::AssailReport = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.coverage.inputs.len(), 3);
    for (original, decoded) in report.coverage.inputs.iter().zip(&restored.coverage.inputs) {
        assert_eq!(original.path, decoded.path);
    }
    // Rebuilding the index must still allow each colliding display path to be
    // marked independently after loading the saved report.
    restored.coverage.finish();
    for (i, path) in paths.iter().enumerate() {
        restored
            .coverage
            .mark(path, "unsupported", Some(i.to_string()), None);
        let input = restored
            .coverage
            .inputs
            .iter()
            .find(|input| &input.path == path)
            .unwrap();
        assert_eq!(input.reason, Some(i.to_string()));
    }

    let inputs = value["coverage"]["inputs"].as_array().unwrap();
    for path in &paths {
        let input = inputs.iter().find(|input| {
            input["path_bytes_hex"].as_str()
                == Some(hex::encode(path.as_os_str().as_bytes()).as_str())
        });
        if path.to_str().is_some() {
            assert!(input.is_none());
            assert_eq!(
                inputs
                    .iter()
                    .filter(|input| input.get("path_bytes_hex").is_none())
                    .count(),
                1
            );
        } else {
            let mut invalid = input.unwrap().clone();
            invalid["path_bytes_hex"] = serde_json::json!("not hex");
            assert!(serde_json::from_value::<assail::coverage::InputCoverage>(invalid).is_err());
        }
    }
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
