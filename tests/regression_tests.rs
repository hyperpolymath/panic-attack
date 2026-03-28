// SPDX-License-Identifier: PMPL-1.0-or-later

//! Regression tests against known codebases

use panic_attack::assail;
use std::path::Path;

#[test]
#[ignore] // Run with --ignored flag, requires repos
fn test_echidna_baseline() {
    let echidna_path = Path::new("/var$REPOS_DIR/echidna");

    if !echidna_path.exists() {
        eprintln!("⚠️  Skipping: echidna repo not found");
        return;
    }

    let report = assail::analyze(echidna_path).expect("echidna analysis should succeed");

    // v0.2 baseline: 15 weak points (down from 271 in v0.1)
    assert_eq!(report.language, panic_attack::types::Language::Rust);
    assert!(
        report.weak_points.len() >= 10 && report.weak_points.len() <= 20,
        "Expected 10-20 weak points, got {}",
        report.weak_points.len()
    );

    // All weak points must have locations
    for wp in &report.weak_points {
        assert!(
            wp.location.is_some(),
            "Weak point missing location: {:?}",
            wp
        );
    }

    // Should detect multiple frameworks
    assert!(!report.frameworks.is_empty());

    // Should have file statistics
    assert!(!report.file_statistics.is_empty());
    assert!(
        report.file_statistics.len() >= 40,
        "Expected 40+ files with findings"
    );

    println!(
        "✅ echidna baseline validated: {} weak points",
        report.weak_points.len()
    );
}

#[test]
#[ignore] // Run with --ignored flag, requires repos
fn test_eclexia_baseline() {
    let eclexia_path = Path::new("/var$REPOS_DIR/eclexia");

    if !eclexia_path.exists() {
        eprintln!("⚠️  Skipping: eclexia repo not found");
        return;
    }

    let report = assail::analyze(eclexia_path).expect("eclexia analysis should succeed");

    // v0.2 baseline: 7 weak points
    assert_eq!(report.language, panic_attack::types::Language::Rust);
    assert!(
        report.weak_points.len() >= 5 && report.weak_points.len() <= 10,
        "Expected 5-10 weak points, got {}",
        report.weak_points.len()
    );

    // All weak points must have locations
    for wp in &report.weak_points {
        assert!(
            wp.location.is_some(),
            "Weak point missing location: {:?}",
            wp
        );
    }

    // Should have file statistics
    assert!(!report.file_statistics.is_empty());
    assert!(
        report.file_statistics.len() >= 40,
        "Expected 40+ files with findings"
    );

    println!(
        "✅ eclexia baseline validated: {} weak points",
        report.weak_points.len()
    );
}

#[test]
#[ignore] // Run with --ignored flag, requires repos
fn test_panic_attacker_on_itself() {
    let self_path = Path::new(env!("CARGO_MANIFEST_DIR"));

    let report = assail::analyze(self_path).expect("self-analysis should succeed");

    assert_eq!(report.language, panic_attack::types::Language::Rust);

    // panic-attacker should have minimal weak points (it's well-tested)
    assert!(
        report.weak_points.len() <= 5,
        "panic-attacker should have ≤5 weak points, got {}",
        report.weak_points.len()
    );

    // All locations populated
    for wp in &report.weak_points {
        assert!(wp.location.is_some());
    }

    println!(
        "✅ Self-test passed: {} weak points found",
        report.weak_points.len()
    );
}
