// SPDX-License-Identifier: MPL-2.0

//! Tests for the report generation and formatting modules.
//!
//! All tests are panic-free: they return `Result` and propagate errors with
//! `?` instead of calling `.unwrap()`.

use panic_attack::report::{self, ReportOutputFormat};
use panic_attack::types::*;
use std::path::PathBuf;
use std::time::Duration;

fn make_assail_report() -> AssailReport {
    AssailReport {
        schema_version: "2.5".to_string(),
        program_path: PathBuf::from("/tmp/test-program"),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![
            WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some("src/main.rs".to_string()),
                file: None,
                line: None,
                severity: Severity::Critical,
                description: "2 unsafe blocks in src/main.rs".to_string(),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                suppressed: false,
        test_context: None,
            },
            WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some("src/lib.rs".to_string()),
                file: None,
                line: None,
                severity: Severity::Medium,
                description: "5 unwrap/expect calls in src/lib.rs".to_string(),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
        test_context: None,
            },
        ],
        statistics: ProgramStatistics {
            total_lines: 1000,
            unsafe_blocks: 2,
            panic_sites: 1,
            unwrap_calls: 5,
            safe_unwrap_calls: 0,
            allocation_sites: 10,
            io_operations: 3,
            threading_constructs: 1,
        },
        file_statistics: vec![],
        dependency_graph: DependencyGraph { edges: vec![] },
        taint_matrix: TaintMatrix { rows: vec![] },
        recommended_attacks: vec![AttackAxis::Memory, AttackAxis::Concurrency],
        migration_metrics: None,
        suppressed_count: 0,
    }
}

fn make_attack_result(axis: AttackAxis, success: bool, crashes: usize) -> AttackResult {
    let crash_reports: Vec<CrashReport> = (0..crashes)
        .map(|_| CrashReport {
            schema_version: "2.5".to_string(),
            timestamp: "2026-03-01T00:00:00Z".to_string(),
            signal: Some("SIGSEGV".to_string()),
            backtrace: None,
            stderr: "segfault".to_string(),
            stdout: String::new(),
        })
        .collect();
    AttackResult {
        program: PathBuf::from("/tmp/test-program"),
        axis,
        success,
        skipped: false,
        skip_reason: None,
        exit_code: if success { Some(0) } else { Some(139) },
        duration: Duration::from_millis(100),
        peak_memory: 1024,
        crashes: crash_reports,
        signatures_detected: vec![],
    }
}

#[test]
fn test_generate_assault_report_clean() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results)?;
    assert_eq!(report.total_crashes, 0);
    assert_eq!(report.total_signatures, 0);
    assert_eq!(report.attack_results.len(), 1);
    assert!(report.attack_results[0].success);
    Ok(())
}

#[test]
fn test_generate_assault_report_with_crashes() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![
        make_attack_result(AttackAxis::Cpu, true, 0),
        make_attack_result(AttackAxis::Memory, false, 2),
    ];

    let report = report::generate_assault_report(assail, results)?;
    assert_eq!(report.total_crashes, 2);
    assert_eq!(report.attack_results.len(), 2);
    Ok(())
}

#[test]
fn test_robustness_score_perfect() -> Result<(), Box<dyn std::error::Error>> {
    let mut assail = make_assail_report();
    assail.statistics.unsafe_blocks = 0;
    assail
        .weak_points
        .retain(|w| w.severity != Severity::Critical);
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results)?;
    assert!(
        report.overall_assessment.robustness_score > 90.0,
        "clean scan with no crashes should score above 90, got {}",
        report.overall_assessment.robustness_score
    );
    Ok(())
}

#[test]
fn test_robustness_score_with_critical_findings() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report(); // has 1 critical + 2 unsafe blocks
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results)?;
    assert!(
        report.overall_assessment.robustness_score <= 70.0,
        "critical findings should reduce score, got {}",
        report.overall_assessment.robustness_score
    );
    Ok(())
}

#[test]
fn test_robustness_score_clamped_to_zero() -> Result<(), Box<dyn std::error::Error>> {
    let mut assail = make_assail_report();
    for i in 0..10 {
        assail.weak_points.push(WeakPoint {
            category: WeakPointCategory::UnsafeCode,
            location: Some(format!("src/file{}.rs", i)),
            file: None,
            line: None,
            severity: Severity::Critical,
            description: format!("critical issue {}", i),
            recommended_attack: vec![],
            suppressed: false,
        test_context: None,
        });
    }
    let results = vec![make_attack_result(AttackAxis::Memory, false, 5)];

    let report = report::generate_assault_report(assail, results)?;
    assert_eq!(
        report.overall_assessment.robustness_score, 0.0,
        "score should be clamped to 0"
    );
    Ok(())
}

#[test]
fn test_recommendations_generated() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results)?;
    assert!(
        !report.overall_assessment.recommendations.is_empty(),
        "should generate recommendations for code with unsafe blocks and unwrap calls"
    );
    Ok(())
}

#[test]
fn test_critical_issues_from_crashes() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Memory, false, 3)];

    let report = report::generate_assault_report(assail, results)?;
    assert!(
        report
            .overall_assessment
            .critical_issues
            .iter()
            .any(|issue| issue.contains("crashed under Memory")),
        "should flag crash axis in critical issues"
    );
    Ok(())
}

#[test]
fn test_json_serialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results)?;

    let json = ReportOutputFormat::Json.serialize(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    assert!(parsed["assail_report"]["language"].is_string());
    assert!(parsed["overall_assessment"]["robustness_score"].is_number());
    Ok(())
}

#[test]
fn test_yaml_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results)?;

    let yaml = ReportOutputFormat::Yaml.serialize(&report)?;
    assert!(
        yaml.contains("robustness_score"),
        "YAML should contain score field"
    );
    assert!(yaml.contains("rust"), "YAML should contain language");
    Ok(())
}

#[test]
fn test_sarif_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results)?;

    let sarif = ReportOutputFormat::Sarif.serialize(&report)?;
    let parsed: serde_json::Value = serde_json::from_str(&sarif)?;
    assert!(parsed["$schema"].is_string());
    assert!(parsed["runs"].is_array());
    Ok(())
}
