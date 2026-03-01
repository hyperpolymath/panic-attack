// SPDX-License-Identifier: PMPL-1.0-or-later

//! Tests for the assemblyline subcommand (batch repo scanning)

use panic_attack::assemblyline::{self, AssemblylineConfig};
use std::fs;
use tempfile::TempDir;

fn make_git_repo(parent: &std::path::Path, name: &str, content: Option<(&str, &str)>) {
    let repo = parent.join(name);
    fs::create_dir_all(repo.join(".git")).unwrap();
    if let Some((filename, body)) = content {
        fs::write(repo.join(filename), body).unwrap();
    }
}

#[test]
fn test_assemblyline_empty_directory() {
    let dir = TempDir::new().unwrap();
    let config = AssemblylineConfig {
        directory: dir.path().to_path_buf(),
        output: None,
        findings_only: false,
        min_findings: 0,
        sarif: false,
    };

    let report = assemblyline::run(&config).expect("assemblyline should succeed on empty dir");
    assert_eq!(report.repos_scanned, 0);
    assert_eq!(report.total_weak_points, 0);
    assert!(report.results.is_empty());
}

#[test]
fn test_assemblyline_discovers_git_repos_only() {
    let dir = TempDir::new().unwrap();

    // Create a git repo
    make_git_repo(dir.path(), "repo-a", None);

    // Create a non-git directory
    fs::create_dir_all(dir.path().join("not-a-repo")).unwrap();
    fs::write(dir.path().join("not-a-repo/README.md"), "hello").unwrap();

    // Create a plain file (should be ignored)
    fs::write(dir.path().join("stray-file.txt"), "hello").unwrap();

    let config = AssemblylineConfig {
        directory: dir.path().to_path_buf(),
        output: None,
        findings_only: false,
        min_findings: 0,
        sarif: false,
    };

    let report = assemblyline::run(&config).expect("assemblyline should succeed");
    assert_eq!(
        report.repos_scanned, 1,
        "should only discover the git repo, not the plain directory"
    );
}

#[test]
fn test_assemblyline_multiple_repos() {
    let dir = TempDir::new().unwrap();

    // Create two git repos with Rust source
    make_git_repo(dir.path(), "repo-safe", Some(("main.rs", "fn main() {}")));
    make_git_repo(
        dir.path(),
        "repo-risky",
        Some((
            "danger.rs",
            r#"
fn main() {
    unsafe { std::ptr::null::<i32>().read() };
    let x = Some(5).unwrap();
    let y = Some(6).expect("boom");
}
"#,
        )),
    );

    let config = AssemblylineConfig {
        directory: dir.path().to_path_buf(),
        output: None,
        findings_only: false,
        min_findings: 0,
        sarif: false,
    };

    let report = assemblyline::run(&config).expect("assemblyline should succeed");
    assert_eq!(report.repos_scanned, 2);

    // Results should be sorted by weak point count descending
    if report.results.len() == 2 {
        assert!(
            report.results[0].weak_point_count >= report.results[1].weak_point_count,
            "results should be sorted by weak point count descending"
        );
    }
}

#[test]
fn test_assemblyline_findings_only_filter() {
    let dir = TempDir::new().unwrap();

    // A clean repo (no source files = no findings)
    make_git_repo(dir.path(), "clean-repo", None);

    // A repo with findings
    make_git_repo(
        dir.path(),
        "dirty-repo",
        Some((
            "bad.rs",
            r#"
fn main() {
    unsafe { std::ptr::null::<i32>().read() };
}
"#,
        )),
    );

    let config = AssemblylineConfig {
        directory: dir.path().to_path_buf(),
        output: None,
        findings_only: true,
        min_findings: 0,
        sarif: false,
    };

    let report = assemblyline::run(&config).expect("assemblyline should succeed");
    // All results should have findings
    for result in &report.results {
        assert!(
            result.weak_point_count > 0,
            "findings_only should filter out repos with 0 findings"
        );
    }
}

#[test]
fn test_assemblyline_write_report() {
    let dir = TempDir::new().unwrap();
    make_git_repo(dir.path(), "test-repo", Some(("main.rs", "fn main() {}")));

    let config = AssemblylineConfig {
        directory: dir.path().to_path_buf(),
        output: None,
        findings_only: false,
        min_findings: 0,
        sarif: false,
    };

    let report = assemblyline::run(&config).expect("assemblyline should succeed");

    let output_path = dir.path().join("assemblyline-output.json");
    assemblyline::write_report(&report, &output_path).expect("write_report should succeed");

    // Verify the file exists and is valid JSON
    let content = fs::read_to_string(&output_path).expect("should read output file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("should be valid JSON");

    assert!(parsed["repos_scanned"].is_number());
    assert!(parsed["results"].is_array());
}

#[test]
fn test_assemblyline_not_a_directory() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("not-a-dir.txt");
    fs::write(&file_path, "hello").unwrap();

    let config = AssemblylineConfig {
        directory: file_path,
        output: None,
        findings_only: false,
        min_findings: 0,
        sarif: false,
    };

    let result = assemblyline::run(&config);
    assert!(
        result.is_err(),
        "assemblyline should error when given a file instead of directory"
    );
}
