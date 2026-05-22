// SPDX-License-Identifier: MPL-2.0

//! Integration tests for panic-attacker v0.2

use panic_attack::assail;
use panic_attack::types::*;
use std::path::Path;

#[test]
fn test_assail_vulnerable_program() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs");
    let report = assail::analyze(&example).expect("analysis should succeed");

    // Should detect the language
    assert_eq!(report.language, Language::Rust);

    // Should find weak points with locations set
    assert!(
        !report.weak_points.is_empty(),
        "vulnerable_program.rs should produce weak points"
    );
    for wp in &report.weak_points {
        assert!(
            wp.location.is_some(),
            "weak point {:?} should have a file location, got None",
            wp.category
        );
    }

    // Statistics should be populated
    assert!(report.statistics.total_lines > 0);
    assert!(
        report.statistics.unwrap_calls > 0,
        "vulnerable_program.rs contains .unwrap() calls"
    );
    assert!(
        report.statistics.unsafe_blocks > 0,
        "vulnerable_program.rs contains unsafe blocks"
    );
    assert!(
        report.statistics.threading_constructs > 0,
        "vulnerable_program.rs uses std::sync"
    );
}

#[test]
fn test_assail_no_duplicates() {
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let report = assail::analyze(&examples_dir).expect("analysis should succeed");

    // Check no duplicate (category, location) pairs
    let mut seen = std::collections::HashSet::new();
    for wp in &report.weak_points {
        let key = (format!("{:?}", wp.category), wp.location.clone());
        assert!(
            seen.insert(key.clone()),
            "duplicate weak point: {:?} at {:?}",
            key.0,
            key.1
        );
    }
}

#[test]
fn test_assail_per_file_stats() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable_program.rs");
    let report = assail::analyze(&example).expect("analysis should succeed");

    // file_statistics should be populated for a file with findings
    assert!(
        !report.file_statistics.is_empty(),
        "file_statistics should contain entries for files with findings"
    );

    for fs in &report.file_statistics {
        assert!(!fs.file_path.is_empty(), "file_path should not be empty");
        assert!(fs.lines > 0, "lines should be > 0 for source files");
    }
}
