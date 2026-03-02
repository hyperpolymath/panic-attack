// SPDX-License-Identifier: PMPL-1.0-or-later

//! Tests for the report generation and formatting modules

use panic_attack::report::{self, ReportOutputFormat};
use panic_attack::types::*;
use std::path::PathBuf;
use std::time::Duration;

fn make_assail_report() -> AssailReport {
    AssailReport {
        program_path: PathBuf::from("/tmp/test-program"),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![
            WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some("src/main.rs".to_string()),
                severity: Severity::Critical,
                description: "2 unsafe blocks in src/main.rs".to_string(),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
            },
            WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some("src/lib.rs".to_string()),
                severity: Severity::Medium,
                description: "5 unwrap/expect calls in src/lib.rs".to_string(),
                recommended_attack: vec![AttackAxis::Memory],
            },
        ],
        statistics: ProgramStatistics {
            total_lines: 1000,
            unsafe_blocks: 2,
            panic_sites: 1,
            unwrap_calls: 5,
            allocation_sites: 10,
            io_operations: 3,
            threading_constructs: 1,
        },
        file_statistics: vec![],
        dependency_graph: DependencyGraph { edges: vec![] },
        taint_matrix: TaintMatrix { rows: vec![] },
        recommended_attacks: vec![AttackAxis::Memory, AttackAxis::Concurrency],
        migration_metrics: None,
    }
}

fn make_attack_result(axis: AttackAxis, success: bool, crashes: usize) -> AttackResult {
    let crash_reports: Vec<CrashReport> = (0..crashes)
        .map(|_| CrashReport {
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
fn test_generate_assault_report_clean() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert_eq!(report.total_crashes, 0);
    assert_eq!(report.total_signatures, 0);
    assert_eq!(report.attack_results.len(), 1);
    assert!(report.attack_results[0].success);
}

#[test]
fn test_generate_assault_report_with_crashes() {
    let assail = make_assail_report();
    let results = vec![
        make_attack_result(AttackAxis::Cpu, true, 0),
        make_attack_result(AttackAxis::Memory, false, 2),
    ];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert_eq!(report.total_crashes, 2);
    assert_eq!(report.attack_results.len(), 2);
}

#[test]
fn test_robustness_score_perfect() {
    // No unsafe blocks, no crashes → should be high score
    let mut assail = make_assail_report();
    assail.statistics.unsafe_blocks = 0;
    assail.weak_points.retain(|w| w.severity != Severity::Critical);
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert!(
        report.overall_assessment.robustness_score > 90.0,
        "clean scan with no crashes should score above 90, got {}",
        report.overall_assessment.robustness_score
    );
}

#[test]
fn test_robustness_score_with_critical_findings() {
    let assail = make_assail_report(); // has 1 critical + 2 unsafe blocks
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results).unwrap();
    // 100 - 20 (1 critical) - 10 (2 unsafe * 5) = 70
    assert!(
        report.overall_assessment.robustness_score <= 70.0,
        "critical findings should reduce score, got {}",
        report.overall_assessment.robustness_score
    );
}

#[test]
fn test_robustness_score_clamped_to_zero() {
    let mut assail = make_assail_report();
    // Add many critical findings to push score below zero
    for i in 0..10 {
        assail.weak_points.push(WeakPoint {
            category: WeakPointCategory::UnsafeCode,
            location: Some(format!("src/file{}.rs", i)),
            severity: Severity::Critical,
            description: format!("critical issue {}", i),
            recommended_attack: vec![],
        });
    }
    let results = vec![make_attack_result(AttackAxis::Memory, false, 5)];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert_eq!(
        report.overall_assessment.robustness_score, 0.0,
        "score should be clamped to 0"
    );
}

#[test]
fn test_recommendations_generated() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert!(
        !report.overall_assessment.recommendations.is_empty(),
        "should generate recommendations for code with unsafe blocks and unwrap calls"
    );
}

#[test]
fn test_critical_issues_from_crashes() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Memory, false, 3)];

    let report = report::generate_assault_report(assail, results).unwrap();
    assert!(
        report
            .overall_assessment
            .critical_issues
            .iter()
            .any(|issue| issue.contains("crashed under Memory")),
        "should flag crash axis in critical issues"
    );
}

#[test]
fn test_json_serialization_roundtrip() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results).unwrap();

    let json = ReportOutputFormat::Json.serialize(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["assail_report"]["language"].is_string());
    assert!(parsed["overall_assessment"]["robustness_score"].is_number());
}

#[test]
fn test_yaml_serialization() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results).unwrap();

    let yaml = ReportOutputFormat::Yaml.serialize(&report).unwrap();
    assert!(yaml.contains("robustness_score"), "YAML should contain score field");
    assert!(yaml.contains("rust"), "YAML should contain language");
}

#[test]
fn test_sarif_serialization() {
    let assail = make_assail_report();
    let results = vec![make_attack_result(AttackAxis::Cpu, true, 0)];
    let report = report::generate_assault_report(assail, results).unwrap();

    let sarif = ReportOutputFormat::Sarif.serialize(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert!(parsed["$schema"].is_string());
    assert!(parsed["runs"].is_array());
}
