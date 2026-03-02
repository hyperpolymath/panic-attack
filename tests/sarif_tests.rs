// SPDX-License-Identifier: PMPL-1.0-or-later

//! Tests for SARIF 2.1.0 output format

use panic_attack::assail;
use panic_attack::report::sarif;
use panic_attack::types::*;
use std::path::Path;

fn make_test_report() -> AssailReport {
    AssailReport {
        program_path: ".".into(),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![
            WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                severity: Severity::Critical,
                description: "unsafe block found".to_string(),
                location: Some("src/main.rs:10".to_string()),
                recommended_attack: vec![AttackAxis::Memory],
            },
            WeakPoint {
                category: WeakPointCategory::PanicPath,
                severity: Severity::Medium,
                description: "unwrap on Option".to_string(),
                location: Some("src/lib.rs:42".to_string()),
                recommended_attack: vec![],
            },
        ],
        statistics: ProgramStatistics::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
    }
}

#[test]
fn test_sarif_valid_json() {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");

    // Should be valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("SARIF output should be valid JSON");

    // Should be an object
    assert!(parsed.is_object());
}

#[test]
fn test_sarif_schema_and_version() {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Check version
    assert_eq!(parsed["version"], "2.1.0");

    // Check schema
    let schema = parsed["$schema"].as_str().unwrap();
    assert!(
        schema.contains("sarif-schema-2.1.0"),
        "schema should reference SARIF 2.1.0"
    );
}

#[test]
fn test_sarif_has_runs() {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let runs = parsed["runs"].as_array().expect("runs should be an array");
    assert_eq!(runs.len(), 1, "should have exactly one run");
}

#[test]
fn test_sarif_tool_info() {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let driver = &parsed["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "panic-attack");
    assert!(driver["version"].as_str().is_some());
    assert!(driver["informationUri"].as_str().is_some());
}

#[test]
fn test_sarif_results_populated() {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let results = parsed["runs"][0]["results"]
        .as_array()
        .expect("results should be an array");
    assert_eq!(results.len(), 2, "should have 2 results");

    // Check first result
    let r0 = &results[0];
    assert_eq!(r0["ruleId"], "PA004"); // UnsafeCode
    assert_eq!(r0["level"], "error"); // Critical -> error
    assert_eq!(r0["message"]["text"], "unsafe block found");

    // Check location
    let loc = &r0["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "src/main.rs");
    assert_eq!(loc["region"]["startLine"], 10);

    // Check second result
    let r1 = &results[1];
    assert_eq!(r1["ruleId"], "PA005"); // PanicPath
    assert_eq!(r1["level"], "warning"); // Medium -> warning
}

#[test]
fn test_sarif_rules_deduplicated() {
    let report = make_test_report();
    let log = sarif::to_sarif(&report).expect("SARIF conversion should succeed");

    let rules = &log.runs[0].tool.driver.rules;
    // Two distinct categories: UnsafeCode and PanicPath
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].id, "PA004");
    assert_eq!(rules[1].id, "PA005");
}

#[test]
fn test_sarif_empty_report() {
    let report = AssailReport {
        program_path: ".".into(),
        language: Language::Unknown,
        frameworks: vec![],
        weak_points: vec![],
        statistics: ProgramStatistics::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
    };

    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty(), "empty report should produce 0 results");
}

#[test]
fn test_sarif_from_real_analysis() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs");
    let report = assail::analyze(&example).expect("analysis should succeed");

    let json = sarif::to_sarif_json(&report).expect("SARIF conversion should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Real analysis should produce results
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.is_empty(),
        "real analysis should produce SARIF results"
    );

    // All results should have valid structure
    for result in results {
        assert!(result["ruleId"].as_str().is_some());
        assert!(result["level"].as_str().is_some());
        assert!(result["message"]["text"].as_str().is_some());
        assert!(!result["locations"].as_array().unwrap().is_empty());
    }
}
