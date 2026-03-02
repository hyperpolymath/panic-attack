// SPDX-License-Identifier: PMPL-1.0-or-later

//! Tests for the PanLL event-chain export module

use panic_attack::panll;
use panic_attack::types::*;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn make_assault_report(
    weak_points: Vec<WeakPoint>,
    attack_results: Vec<AttackResult>,
) -> AssaultReport {
    let _critical_count = weak_points.iter().filter(|wp| wp.severity == Severity::Critical).count();
    let unsafe_count = weak_points.iter().filter(|wp| wp.category == WeakPointCategory::UnsafeCode).count();

    AssaultReport {
        assail_report: AssailReport {
            program_path: PathBuf::from("/tmp/test-target"),
            language: Language::Rust,
            frameworks: vec![],
            weak_points,
            statistics: ProgramStatistics {
                total_lines: 500,
                unsafe_blocks: unsafe_count,
                panic_sites: 0,
                unwrap_calls: 3,
                allocation_sites: 5,
                io_operations: 1,
                threading_constructs: 0,
            },
            file_statistics: vec![],
            dependency_graph: DependencyGraph { edges: vec![] },
            taint_matrix: TaintMatrix { rows: vec![] },
            recommended_attacks: vec![],
            migration_metrics: None,
        },
        attack_results,
        total_crashes: 0,
        total_signatures: 0,
        overall_assessment: OverallAssessment {
            robustness_score: 75.0,
            critical_issues: vec![],
            recommendations: vec![],
        },
        timeline: None,
    }
}

#[test]
fn test_panll_export_writes_valid_json() {
    let report = make_assault_report(vec![], vec![]);
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["format"], "panll.event-chain.v0");
    assert_eq!(parsed["source"]["tool"], "panic-attack");
}

#[test]
fn test_panll_export_summary_reflects_report() {
    let report = make_assault_report(
        vec![WeakPoint {
            category: WeakPointCategory::UnsafeCode,
            location: Some("src/lib.rs".to_string()),
            severity: Severity::Critical,
            description: "unsafe block".to_string(),
            recommended_attack: vec![],
        }],
        vec![],
    );
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["summary"]["weak_points"], 1);
    assert_eq!(parsed["summary"]["critical_weak_points"], 1);
    assert_eq!(parsed["summary"]["robustness_score"], 75.0);
}

#[test]
fn test_panll_export_constraints_from_critical_wp() {
    let report = make_assault_report(
        vec![
            WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some("src/danger.rs".to_string()),
                severity: Severity::Critical,
                description: "transmute usage".to_string(),
                recommended_attack: vec![AttackAxis::Memory],
            },
            WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some("src/safe.rs".to_string()),
                severity: Severity::Medium,
                description: "unwrap call".to_string(),
                recommended_attack: vec![],
            },
        ],
        vec![],
    );
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let constraints = parsed["constraints"].as_array().unwrap();

    // Only the critical WP should generate a constraint, not the medium one
    assert_eq!(constraints.len(), 1, "only critical WPs become constraints");
    assert!(constraints[0]["id"].as_str().unwrap().starts_with("wp-crit-"));
    assert!(constraints[0]["description"]
        .as_str()
        .unwrap()
        .contains("transmute"));
}

#[test]
fn test_panll_export_event_chain_from_attacks() {
    let report = make_assault_report(
        vec![],
        vec![
            AttackResult {
                program: PathBuf::from("/tmp/target"),
                axis: AttackAxis::Cpu,
                success: true,
                skipped: false,
                skip_reason: None,
                exit_code: Some(0),
                duration: Duration::from_millis(500),
                peak_memory: 1024,
                crashes: vec![],
                signatures_detected: vec![],
            },
            AttackResult {
                program: PathBuf::from("/tmp/target"),
                axis: AttackAxis::Memory,
                success: false,
                skipped: false,
                skip_reason: None,
                exit_code: Some(139),
                duration: Duration::from_millis(200),
                peak_memory: 4096,
                crashes: vec![],
                signatures_detected: vec![],
            },
        ],
    );
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let events = parsed["event_chain"].as_array().unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["axis"], "cpu");
    assert_eq!(events[0]["status"], "passed");
    assert_eq!(events[1]["axis"], "memory");
    assert_eq!(events[1]["status"], "failed");
}

#[test]
fn test_panll_export_constraints_from_failed_attacks() {
    let mut report = make_assault_report(
        vec![],
        vec![AttackResult {
            program: PathBuf::from("/tmp/target"),
            axis: AttackAxis::Concurrency,
            success: false,
            skipped: false,
            skip_reason: None,
            exit_code: Some(1),
            duration: Duration::from_millis(100),
            peak_memory: 0,
            crashes: vec![CrashReport {
                timestamp: "2026-03-01T00:00:00Z".to_string(),
                signal: Some("SIGSEGV".to_string()),
                backtrace: None,
                stderr: "segfault".to_string(),
                stdout: String::new(),
            }],
            signatures_detected: vec![],
        }],
    );
    report.total_crashes = 1;

    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let constraints = parsed["constraints"].as_array().unwrap();

    assert!(
        constraints.iter().any(|c| c["id"]
            .as_str()
            .unwrap()
            .starts_with("attack-fail-")),
        "failed attack should generate a constraint"
    );
}

#[test]
fn test_panll_export_skipped_attacks_not_in_constraints() {
    let report = make_assault_report(
        vec![],
        vec![AttackResult {
            program: PathBuf::from("/tmp/target"),
            axis: AttackAxis::Network,
            success: false,
            skipped: true,
            skip_reason: Some("probe: missing flags".to_string()),
            exit_code: None,
            duration: Duration::from_millis(0),
            peak_memory: 0,
            crashes: vec![],
            signatures_detected: vec![],
        }],
    );

    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");

    panll::write_export(&report, None, &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let constraints = parsed["constraints"].as_array().unwrap();

    assert!(
        constraints.is_empty(),
        "skipped attacks should not generate constraints"
    );

    let events = parsed["event_chain"].as_array().unwrap();
    assert_eq!(events[0]["status"], "skipped");
}

#[test]
fn test_panll_export_report_path_recorded() {
    let report = make_assault_report(vec![], vec![]);
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("panll-out.json");
    let source_path = std::path::Path::new("/tmp/my-report.json");

    panll::write_export(&report, Some(source_path), &output).unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["source"]["report_path"], "/tmp/my-report.json");
}
