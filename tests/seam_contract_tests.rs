// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Seam contract tests — pin the JSON schema fields consumed by downstream
//! tools (panicbot, Hypatia, PanLL) so schema drift is caught in CI before
//! it silently breaks a consumer.
//!
//! These tests do NOT check runtime behaviour — they verify that the
//! serialized JSON of each report type contains the exact field names that
//! external consumers depend on. A field rename or removal will fail here,
//! forcing a conscious migration rather than a silent breakage.
//!
//! ## Consumer map
//! - **panicbot** (`gitbot-fleet/bots/panicbot/translator.rs`):
//!   reads `weak_points[].category`, `.location`, `.severity`, `.suppressed`
//!   and `statistics.unwrap_calls`, `statistics.unsafe_blocks`
//! - **Hypatia** (Elixir rules):
//!   reads `weak_points[].category`, `.severity`, `suppressed_count`,
//!   `language`, `frameworks`
//! - **PanLL** event-chain:
//!   reads `assail_report`, `attack_results`, `overall_assessment.robustness_score`
//! - **Schema version sentinel** (all consumers):
//!   reads `schema_version` to detect incompatible changes

use panic_attack::abduct::AbductReport;
use panic_attack::amuck::AmuckReport;
use panic_attack::axial::AxialReport;
use panic_attack::types::*;
use serde_json::Value;

// ─── Helpers ─────────────────────────────────────────────────────────────

fn minimal_assail_report() -> AssailReport {
    AssailReport {
        schema_version: "2.5".to_string(),
        program_path: std::path::PathBuf::from("/tmp/test"),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![WeakPoint {
            category: WeakPointCategory::PanicPath,
            location: Some("src/main.rs:42".to_string()),
            file: Some("src/main.rs".to_string()),
            line: Some(42),
            severity: Severity::Medium,
            description: "unwrap calls".to_string(),
            recommended_attack: vec![AttackAxis::Memory],
            suppressed: false,
        test_context: None,
        }],
        statistics: ProgramStatistics {
            total_lines: 100,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 6,
            safe_unwrap_calls: 3,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        },
        file_statistics: vec![],
        recommended_attacks: vec![AttackAxis::Memory],
        dependency_graph: DependencyGraph::default(),
        taint_matrix: TaintMatrix::default(),
        migration_metrics: None,
        suppressed_count: 0,
    }
}

// ─── AssailReport seam (panicbot + Hypatia) ──────────────────────────────

#[test]
fn assail_report_has_schema_version() {
    let report = minimal_assail_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        json["schema_version"].as_str(),
        Some("2.5"),
        "schema_version must be present and equal '2.5'"
    );
}

#[test]
fn assail_report_panicbot_fields_present() {
    let report = minimal_assail_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");

    // panicbot reads these fields from every AssailReport
    assert!(json["weak_points"].is_array(), "weak_points must be array");
    let wp = &json["weak_points"][0];
    assert!(
        wp["category"].is_string(),
        "weak_points[].category must be string"
    );
    assert!(
        wp["severity"].is_string(),
        "weak_points[].severity must be string"
    );
    assert!(
        wp["location"].is_string(),
        "weak_points[].location must be string (or null)"
    );
    assert!(
        json["statistics"]["unwrap_calls"].is_number(),
        "statistics.unwrap_calls must be number"
    );
    assert!(
        json["statistics"]["unsafe_blocks"].is_number(),
        "statistics.unsafe_blocks must be number"
    );
}

#[test]
fn assail_report_hypatia_fields_present() {
    let report = minimal_assail_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");

    // Hypatia Elixir rules read these
    assert!(json["language"].is_string(), "language must be string");
    assert!(json["frameworks"].is_array(), "frameworks must be array");
    assert!(
        json["suppressed_count"].is_null() || json["suppressed_count"].is_number(),
        "suppressed_count must be number or absent (default 0)"
    );
}

#[test]
fn assail_report_suppressed_field_on_weak_point() {
    let report = minimal_assail_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");

    // panicbot filters on suppressed: false — field must be absent (default)
    // or explicitly false. It must NEVER be missing from a suppressed finding.
    let wp = &json["weak_points"][0];
    // suppressed=false is skip_serializing_if — field should be absent
    assert!(
        wp["suppressed"].is_null(),
        "suppressed=false should be omitted by skip_serializing_if; panicbot treats absent as false"
    );
}

#[test]
fn assail_report_safe_unwrap_calls_present_when_nonzero() {
    let report = minimal_assail_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");

    // safe_unwrap_calls=3 in our fixture — must appear in serialized JSON
    assert_eq!(
        json["statistics"]["safe_unwrap_calls"].as_u64(),
        Some(3),
        "safe_unwrap_calls must serialize when nonzero"
    );
}

#[test]
fn assail_report_safe_unwrap_calls_absent_when_zero() {
    let mut report = minimal_assail_report();
    report.statistics.safe_unwrap_calls = 0;
    let json: Value = serde_json::to_value(&report).expect("serialize");

    // skip_serializing_if = is_zero — field should be absent when 0
    assert!(
        json["statistics"]["safe_unwrap_calls"].is_null(),
        "safe_unwrap_calls=0 should be omitted by skip_serializing_if"
    );
}

// ─── AssaultReport seam (PanLL) ──────────────────────────────────────────

#[test]
fn assault_report_has_schema_version() {
    let assault = AssaultReport {
        schema_version: "2.5".to_string(),
        assail_report: minimal_assail_report(),
        attack_results: vec![],
        total_crashes: 0,
        total_signatures: 0,
        overall_assessment: OverallAssessment {
            robustness_score: 100.0,
            critical_issues: vec![],
            recommendations: vec![],
        },
        timeline: None,
    };
    let json: Value = serde_json::to_value(&assault).expect("serialize");
    assert_eq!(json["schema_version"].as_str(), Some("2.5"));
    assert!(
        json["assail_report"].is_object(),
        "assail_report must be object"
    );
    assert!(
        json["overall_assessment"]["robustness_score"].is_number(),
        "robustness_score must be number"
    );
}

// ─── Category enum stability (panicbot translator hardcodes these strings) ──

#[test]
fn weak_point_category_serialization_stable() {
    let cases: &[(WeakPointCategory, &str)] = &[
        (WeakPointCategory::UnsafeCode, "UnsafeCode"),
        (WeakPointCategory::PanicPath, "PanicPath"),
        (WeakPointCategory::CommandInjection, "CommandInjection"),
        (WeakPointCategory::HardcodedSecret, "HardcodedSecret"),
        (
            WeakPointCategory::UnsafeDeserialization,
            "UnsafeDeserialization",
        ),
        (WeakPointCategory::UncheckedError, "UncheckedError"),
        (WeakPointCategory::UnsafeFFI, "UnsafeFFI"),
        (WeakPointCategory::RaceCondition, "RaceCondition"),
        (WeakPointCategory::ResourceLeak, "ResourceLeak"),
        (WeakPointCategory::PathTraversal, "PathTraversal"),
        (WeakPointCategory::AtomExhaustion, "AtomExhaustion"),
        (WeakPointCategory::ProofDrift, "ProofDrift"),
        (WeakPointCategory::CryptoMisuse, "CryptoMisuse"),
        (WeakPointCategory::SupplyChain, "SupplyChain"),
        (WeakPointCategory::InputBoundary, "InputBoundary"),
        (WeakPointCategory::MutationGap, "MutationGap"),
    ];

    for (cat, expected_str) in cases {
        let json = serde_json::to_value(cat).expect("serialize category");
        assert_eq!(
            json.as_str(),
            Some(*expected_str),
            "WeakPointCategory::{:?} must serialize to {:?} — panicbot's translator.rs hardcodes these strings",
            cat,
            expected_str
        );
    }
}

// ─── Severity enum stability (panicbot + Hypatia) ────────────────────────

#[test]
fn severity_serialization_stable() {
    let cases: &[(Severity, &str)] = &[
        (Severity::Low, "Low"),
        (Severity::Medium, "Medium"),
        (Severity::High, "High"),
        (Severity::Critical, "Critical"),
    ];

    for (sev, expected) in cases {
        let json = serde_json::to_value(sev).expect("serialize severity");
        assert_eq!(
            json.as_str(),
            Some(*expected),
            "Severity::{:?} must serialize to {:?}",
            sev,
            expected
        );
    }
}

// ─── Schema version round-trip ───────────────────────────────────────────

#[test]
fn assail_report_schema_version_survives_round_trip() {
    let report = minimal_assail_report();
    let json_str = serde_json::to_string(&report).expect("serialize");
    let back: AssailReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(back.schema_version, "2.5");
}

#[test]
fn old_report_without_schema_version_deserializes_with_default() {
    // Simulate a v2.4 report (no schema_version field) being read by v2.5 binary.
    // The #[serde(default = "assail_schema_version")] must supply "2.5".
    let json_str = r#"{
        "program_path": "/tmp/test",
        "language": "rust",
        "frameworks": [],
        "weak_points": [],
        "statistics": {
            "total_lines": 0,
            "unsafe_blocks": 0,
            "panic_sites": 0,
            "unwrap_calls": 0,
            "allocation_sites": 0,
            "io_operations": 0,
            "threading_constructs": 0
        },
        "file_statistics": [],
        "recommended_attacks": []
    }"#;
    let report: AssailReport = serde_json::from_str(json_str).expect("deserialize old report");
    assert_eq!(
        report.schema_version, "2.5",
        "old reports missing schema_version must default to current version"
    );
}

// ─── schema_version on CrashReport ──────────────────────────────────────

#[test]
fn crash_report_has_schema_version() {
    let r = CrashReport {
        schema_version: "2.5".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signal: None,
        backtrace: None,
        stderr: String::new(),
        stdout: String::new(),
    };
    let json: Value = serde_json::to_value(&r).expect("serialize");
    assert_eq!(
        json["schema_version"].as_str(),
        Some("2.5"),
        "CrashReport must carry schema_version for schema-drift detection"
    );
}

#[test]
fn crash_report_old_json_defaults_schema_version() {
    let json_str = r#"{"timestamp":"2026-01-01T00:00:00Z","signal":null,"backtrace":null,"stderr":"","stdout":""}"#;
    let r: CrashReport = serde_json::from_str(json_str).expect("deserialize old CrashReport");
    assert_eq!(
        r.schema_version, "2.5",
        "old CrashReport missing schema_version must default to '2.5'"
    );
}

// ─── AbductReport schema pin ─────────────────────────────────────────────

fn minimal_abduct_report() -> AbductReport {
    AbductReport {
        schema_version: "2.5".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        target: std::path::PathBuf::from("src/main.rs"),
        source_root: std::path::PathBuf::from("src"),
        workspace_dir: std::path::PathBuf::from("runtime/abduct/test"),
        dependency_scope: "none".to_string(),
        selected_files: 0,
        locked_files: 0,
        mtime_shifted_files: 0,
        mtime_offset_days: 0,
        time_mode: "normal".to_string(),
        time_scale: None,
        virtual_now: None,
        notes: vec![],
        files: vec![],
        execution: None,
    }
}

#[test]
fn abduct_report_has_schema_version() {
    let report = minimal_abduct_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        json["schema_version"].as_str(),
        Some("2.5"),
        "AbductReport schema_version must be '2.5'"
    );
}

#[test]
fn abduct_report_schema_version_round_trip() {
    let report = minimal_abduct_report();
    let json_str = serde_json::to_string(&report).expect("serialize");
    let back: AbductReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(back.schema_version, "2.5");
}

#[test]
fn old_abduct_report_without_schema_version_deserializes_with_default() {
    let json_str = r#"{
        "created_at": "2026-01-01T00:00:00Z",
        "target": "src/main.rs",
        "source_root": "src",
        "workspace_dir": "runtime/abduct/test",
        "dependency_scope": "none",
        "selected_files": 0,
        "locked_files": 0,
        "mtime_shifted_files": 0,
        "mtime_offset_days": 0,
        "time_mode": "normal"
    }"#;
    let report: AbductReport =
        serde_json::from_str(json_str).expect("deserialize old abduct report");
    assert_eq!(
        report.schema_version, "2.5",
        "old AbductReport missing schema_version must default to '2.5'"
    );
}

// ─── AmuckReport schema pin ──────────────────────────────────────────────

fn minimal_amuck_report() -> AmuckReport {
    AmuckReport {
        schema_version: "2.5".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        target: std::path::PathBuf::from("src/main.rs"),
        source_spec: None,
        preset: "light".to_string(),
        max_combinations: 0,
        output_dir: std::path::PathBuf::from("runtime/amuck"),
        combinations_planned: 0,
        combinations_run: 0,
        outcomes: vec![],
    }
}

#[test]
fn amuck_report_has_schema_version() {
    let report = minimal_amuck_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        json["schema_version"].as_str(),
        Some("2.5"),
        "AmuckReport schema_version must be '2.5'"
    );
}

#[test]
fn amuck_report_schema_version_round_trip() {
    let report = minimal_amuck_report();
    let json_str = serde_json::to_string(&report).expect("serialize");
    let back: AmuckReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(back.schema_version, "2.5");
}

#[test]
fn old_amuck_report_without_schema_version_deserializes_with_default() {
    let json_str = r#"{
        "created_at": "2026-01-01T00:00:00Z",
        "target": "src/main.rs",
        "preset": "light",
        "max_combinations": 0,
        "output_dir": "runtime/amuck",
        "combinations_planned": 0,
        "combinations_run": 0,
        "outcomes": []
    }"#;
    let report: AmuckReport = serde_json::from_str(json_str).expect("deserialize old amuck report");
    assert_eq!(
        report.schema_version, "2.5",
        "old AmuckReport missing schema_version must default to '2.5'"
    );
}

// ─── AxialReport schema pin ──────────────────────────────────────────────

fn minimal_axial_report() -> AxialReport {
    AxialReport {
        schema_version: "2.5".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        target: std::path::PathBuf::from("src/main.rs"),
        executed_program: None,
        repeat: 0,
        observed_runs: 0,
        observed_reports: 0,
        language: "en".to_string(),
        run_observations: vec![],
        report_observations: vec![],
        signal_counts: std::collections::BTreeMap::new(),
        recommendations: vec![],
        aspell: None,
    }
}

#[test]
fn axial_report_has_schema_version() {
    let report = minimal_axial_report();
    let json: Value = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        json["schema_version"].as_str(),
        Some("2.5"),
        "AxialReport schema_version must be '2.5'"
    );
}

#[test]
fn axial_report_schema_version_round_trip() {
    let report = minimal_axial_report();
    let json_str = serde_json::to_string(&report).expect("serialize");
    let back: AxialReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(back.schema_version, "2.5");
}

#[test]
fn old_axial_report_without_schema_version_deserializes_with_default() {
    let json_str = r#"{
        "created_at": "2026-01-01T00:00:00Z",
        "target": "src/main.rs",
        "repeat": 0,
        "observed_runs": 0,
        "observed_reports": 0,
        "language": "en"
    }"#;
    let report: AxialReport = serde_json::from_str(json_str).expect("deserialize old axial report");
    assert_eq!(
        report.schema_version, "2.5",
        "old AxialReport missing schema_version must default to '2.5'"
    );
}
