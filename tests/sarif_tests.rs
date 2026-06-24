// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Tests for SARIF 2.1.0 output format.
//!
//! All tests are panic-free: they return `Result` and propagate errors with
//! `?`. JSON value access uses `.ok_or(...)` rather than `.as_xxx().unwrap()`.

use panic_attack::assail;
use panic_attack::report::sarif;
use panic_attack::types::*;
use std::path::Path;

fn make_test_report() -> AssailReport {
    AssailReport {
        schema_version: "2.5".to_string(),
        program_path: ".".into(),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![
            WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                severity: Severity::Critical,
                description: "unsafe block found".to_string(),
                location: Some("src/main.rs:10".to_string()),
                file: None,
                line: None,
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
        test_context: None,
            },
            WeakPoint {
                category: WeakPointCategory::PanicPath,
                severity: Severity::Medium,
                description: "unwrap on Option".to_string(),
                location: Some("src/lib.rs:42".to_string()),
                file: None,
                line: None,
                recommended_attack: vec![],
                suppressed: false,
        test_context: None,
            },
        ],
        statistics: ProgramStatistics::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
        suppressed_count: 0,
    }
}

#[test]
fn test_sarif_valid_json() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    assert!(parsed.is_object());
    Ok(())
}

#[test]
fn test_sarif_schema_and_version() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    assert_eq!(parsed["version"], "2.1.0");

    let schema = parsed["$schema"]
        .as_str()
        .ok_or("$schema must be a string")?;
    assert!(
        schema.contains("sarif-schema-2.1.0"),
        "schema should reference SARIF 2.1.0"
    );
    Ok(())
}

#[test]
fn test_sarif_has_runs() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    let runs = parsed["runs"].as_array().ok_or("runs must be an array")?;
    assert_eq!(runs.len(), 1, "should have exactly one run");
    Ok(())
}

#[test]
fn test_sarif_tool_info() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    let driver = &parsed["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "panic-attack");
    assert!(driver["version"].as_str().is_some());
    assert!(driver["informationUri"].as_str().is_some());
    Ok(())
}

#[test]
fn test_sarif_results_populated() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    let results = parsed["runs"][0]["results"]
        .as_array()
        .ok_or("results must be an array")?;
    assert_eq!(results.len(), 2, "should have 2 results");

    let r0 = &results[0];
    assert_eq!(r0["ruleId"], "PA004", "UnsafeCode should map to PA004");
    assert_eq!(r0["level"], "error", "Critical should map to error");
    assert_eq!(r0["message"]["text"], "unsafe block found");

    let loc = &r0["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "src/main.rs");
    assert_eq!(loc["region"]["startLine"], 10);

    let r1 = &results[1];
    assert_eq!(r1["ruleId"], "PA005", "PanicPath should map to PA005");
    assert_eq!(r1["level"], "warning", "Medium should map to warning");
    Ok(())
}

#[test]
fn test_sarif_rules_deduplicated() -> Result<(), Box<dyn std::error::Error>> {
    let report = make_test_report();
    let log = sarif::to_sarif(&report)?;

    let rules = &log.runs[0].tool.driver.rules;
    assert_eq!(
        rules.len(),
        2,
        "two distinct categories: UnsafeCode and PanicPath"
    );
    assert_eq!(rules[0].id, "PA004");
    assert_eq!(rules[1].id, "PA005");
    Ok(())
}

#[test]
fn test_sarif_empty_report() -> Result<(), Box<dyn std::error::Error>> {
    let report = AssailReport {
        schema_version: "2.5".to_string(),
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
        suppressed_count: 0,
    };

    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    let results = parsed["runs"][0]["results"]
        .as_array()
        .ok_or("results must be an array")?;
    assert!(results.is_empty(), "empty report should produce 0 results");
    Ok(())
}

#[test]
fn test_sarif_from_real_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs");
    let report = assail::analyze(&example)?;

    let json = sarif::to_sarif_json(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;

    let results = parsed["runs"][0]["results"]
        .as_array()
        .ok_or("results must be an array")?;
    assert!(
        !results.is_empty(),
        "real analysis should produce SARIF results"
    );

    for result in results {
        assert!(result["ruleId"].as_str().is_some(), "result missing ruleId");
        assert!(result["level"].as_str().is_some(), "result missing level");
        assert!(
            result["message"]["text"].as_str().is_some(),
            "result missing message text"
        );
        let locs = result["locations"]
            .as_array()
            .ok_or("locations must be an array")?;
        assert!(!locs.is_empty(), "result missing locations");
    }
    Ok(())
}
