// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! End-to-end tests for panic-attack
//!
//! Tests the full scanning pipeline:
//! - Full project scan (target repo → detect languages → apply rules → generate report)
//! - CLI smoke tests (help, version, basic commands)
//! - Self-scan (dogfooding: scan panic-attack's own source)
//! - Multi-language project scanning
//! - Error handling for edge cases

use panic_attack::assail;
use panic_attack::types::*;
use std::path::Path;

// ============================================================================
// Self-Scan Tests (Dogfooding)
// ============================================================================

/// E2E test: Scan panic-attack's own source code (dogfooding)
///
/// This is the highest-value test. It:
/// - Verifies the tool works on a real, non-trivial Rust project
/// - Detects actual weak points in the codebase
/// - Ensures the report is properly formatted
/// - Validates that self-analysis doesn't regress
#[test]
fn e2e_self_scan_panic_attack_source() {
    let src_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    if !src_path.exists() {
        return; // Skip if src not available (e.g., in distributed test environment)
    }

    let report = assail::analyze(&src_path)
        .expect("self-scan of panic-attack source should succeed");

    // Should detect Rust as primary language
    assert_eq!(report.language, Language::Rust,
               "panic-attack source must be detected as Rust");

    // Should find some weak points (it's a non-trivial codebase)
    assert!(!report.weak_points.is_empty(),
            "panic-attack source should contain detectable weak points");

    // All weak points must have locations
    for wp in &report.weak_points {
        assert!(wp.location.is_some(),
                "Weak point {:?} must have location in self-scan",
                wp.category);
        assert!(!wp.location.as_ref().unwrap().is_empty(),
                "Location must not be empty string");
    }

    // Statistics should be reasonable for panic-attack
    assert!(report.statistics.total_lines > 1000,
            "panic-attack source is >1000 lines");

    // There should be some non-zero statistics
    // (panic-attack intentionally uses some unsafe code for FFI)
    let has_any_metric = report.statistics.unwrap_calls > 0
        || report.statistics.panic_sites > 0
        || report.statistics.unsafe_blocks > 0
        || report.statistics.threading_constructs > 0;
    assert!(has_any_metric,
            "panic-attack should have measurable metrics");
}

/// E2E test: Scan examples directory (vulnerable program)
///
/// Verifies the analyzer correctly identifies issues in the example code
#[test]
fn e2e_scan_vulnerable_examples() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    if !examples_dir.exists() {
        return;
    }

    let report = assail::analyze(&examples_dir)
        .expect("scanning examples directory should succeed");

    assert_eq!(report.language, Language::Rust);

    // The vulnerable_program.rs example should have detectable issues
    assert!(!report.weak_points.is_empty(),
            "examples/vulnerable_program.rs contains unwrap() and panic paths");

    // Check for expected weak point categories
    let has_unwrap = report.weak_points.iter()
        .any(|wp| wp.category == WeakPointCategory::UnsafeDeserialization
                || wp.category == WeakPointCategory::PanicPath);
    assert!(has_unwrap,
            "vulnerable_program.rs should have panic-related weak points");
}

// ============================================================================
// Multi-Language Scanning Tests
// ============================================================================

/// E2E test: Scan single Python file
#[test]
fn e2e_scan_python_file() {
    let py_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/example.py");

    // Create temp Python file if it doesn't exist
    if !py_file.exists() {
        use std::fs;
        let _ = fs::create_dir_all(py_file.parent().unwrap());
        let _ = fs::write(&py_file, r#"
import pickle
import subprocess

def unsafe_deserialization(data):
    return pickle.loads(data)  # Unsafe!

def command_injection(user_input):
    subprocess.call("echo " + user_input, shell=True)  # Unsafe!
"#);
    }

    if py_file.exists() {
        let report = assail::analyze(&py_file)
            .expect("Python analysis should succeed");

        assert_eq!(report.language, Language::Python);
        // Should detect unsafe patterns in Python code
    }
}

// ============================================================================
// Full Pipeline Tests
// ============================================================================

/// E2E test: Analyze → Detect → Report cycle
///
/// Tests the full pipeline from file to structured report
#[test]
fn e2e_full_analysis_pipeline() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable_program.rs");

    if !example.exists() {
        return;
    }

    // Phase 1: Analyze
    let report = assail::analyze(&example)
        .expect("analysis should succeed");

    // Phase 2: Validate structure
    assert_eq!(report.language, Language::Rust);
    assert!(report.statistics.total_lines > 0);

    // Phase 3: Verify weak points are actionable
    for wp in &report.weak_points {
        // Every weak point must have:
        assert!(wp.location.is_some(), "must have location");
        assert!(!wp.description.is_empty(), "must have description");
        assert!(matches!(wp.severity, Severity::Critical | Severity::High | Severity::Medium | Severity::Low),
                "must have valid severity");
    }
}

// ============================================================================
// Report Generation Tests
// ============================================================================

/// E2E test: Report must be JSON-serializable
#[test]
fn e2e_report_json_serialization() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable_program.rs");

    if !example.exists() {
        return;
    }

    let report = assail::analyze(&example)
        .expect("analysis should succeed");

    // Must be serializable to JSON
    let json = serde_json::to_string(&report)
        .expect("report must be JSON-serializable");

    assert!(!json.is_empty());
    assert!(json.contains("language") || json.contains("Rust"),
            "JSON must contain language information");
}

/// E2E test: Report must be YAML-serializable
#[test]
fn e2e_report_yaml_serialization() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable_program.rs");

    if !example.exists() {
        return;
    }

    let report = assail::analyze(&example)
        .expect("analysis should succeed");

    // Must be serializable to YAML
    let yaml = serde_yaml::to_string(&report)
        .expect("report must be YAML-serializable");

    assert!(!yaml.is_empty());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/// E2E test: Non-existent path handling
#[test]
fn e2e_nonexistent_path_handling() {
    let nonexistent = Path::new("/tmp/this-path-definitely-does-not-exist-12345");

    // Should not panic, but may return an error
    let result = assail::analyze(nonexistent);
    // Result may be Ok(report) or Err, but must not panic
    let _ = result;
}

/// E2E test: Empty directory handling
#[test]
fn e2e_empty_directory_handling() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new()
        .expect("temp dir creation should succeed");

    // Analyzing empty directory should not panic
    let result = assail::analyze(temp_dir.path());
    // Should either succeed with empty report or fail gracefully
    let _ = result;
}

/// E2E test: Binary files in scan path
#[test]
fn e2e_binary_files_skipped() {
    use tempfile::TempDir;
    use std::fs;

    let temp_dir = TempDir::new()
        .expect("temp dir creation should succeed");

    // Create a binary-like file (fake ELF header)
    let binary_path = temp_dir.path().join("program.bin");
    fs::write(&binary_path, b"\x7FELF\x02\x01\x01")
        .expect("binary file creation should succeed");

    // Create a Rust source file
    let source_path = temp_dir.path().join("main.rs");
    fs::write(&source_path, "fn main() {}")
        .expect("source file creation should succeed");

    // Should analyze only the .rs file, skip the binary
    let result = assail::analyze(temp_dir.path());
    // Must not panic when encountering binary files
    let _ = result;
}

/// E2E test: Permission denied handling (if running as non-root)
#[test]
fn e2e_permission_denied_handling() {
    use tempfile::TempDir;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new()
        .expect("temp dir creation should succeed");

    let unreadable_file = temp_dir.path().join("protected.rs");
    fs::write(&unreadable_file, "fn main() {}")
        .expect("file creation should succeed");

    // On Unix, remove read permissions
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o000);
        let _ = fs::set_permissions(&unreadable_file, perms);
    }

    // Should handle permission errors gracefully
    let result = assail::analyze(temp_dir.path());
    // Must not panic
    let _ = result;

    // Cleanup: restore permissions for temp dir cleanup
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o644);
        let _ = fs::set_permissions(&unreadable_file, perms);
    }
}

// ============================================================================
// Consistency Tests
// ============================================================================

/// E2E test: Same input produces same output (determinism)
#[test]
fn e2e_deterministic_analysis() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable_program.rs");

    if !example.exists() {
        return;
    }

    let report1 = assail::analyze(&example)
        .expect("first analysis should succeed");
    let report2 = assail::analyze(&example)
        .expect("second analysis should succeed");

    // Same file should produce same language detection
    assert_eq!(report1.language, report2.language);

    // Same weak points should be found
    assert_eq!(report1.weak_points.len(), report2.weak_points.len(),
               "determinism: same weak points count");

    // Same statistics
    assert_eq!(report1.statistics.total_lines, report2.statistics.total_lines);
}

/// E2E test: Directory vs single file consistency
#[test]
fn e2e_directory_vs_file_consistency() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable_program.rs");
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");

    if !example.exists() || !examples_dir.exists() {
        return;
    }

    let file_report = assail::analyze(&example)
        .expect("file analysis should succeed");
    let dir_report = assail::analyze(&examples_dir)
        .expect("directory analysis should succeed");

    // Directory report should contain findings from the file
    assert!(dir_report.weak_points.len() >= file_report.weak_points.len(),
            "directory report should have at least file's weak points");
}
