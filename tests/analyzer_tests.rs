// SPDX-License-Identifier: PMPL-1.0-or-later

//! Unit tests for language-specific analyzers

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use tempfile::TempDir;

fn create_test_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn test_rust_analyzer_detects_unsafe() {
    let dir = TempDir::new().unwrap();
    let content = r#"
fn main() {
    unsafe {
        let x = std::ptr::null::<i32>();
    }
    unsafe fn dangerous() {}
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert_eq!(report.language, Language::Rust);
    assert!(report.statistics.unsafe_blocks >= 2);
    assert!(!report.weak_points.is_empty());
}

#[test]
fn test_rust_analyzer_detects_unwraps() {
    let dir = TempDir::new().unwrap();
    let content = r#"
fn main() {
    let x = Some(5).unwrap();
    let y = Ok::<i32, ()>(10).expect("should work");
    let z = vec![1,2,3].get(0).unwrap();
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(report.statistics.unwrap_calls >= 3);
}

#[test]
fn test_rust_analyzer_detects_panics() {
    let dir = TempDir::new().unwrap();
    let content = r#"
fn main() {
    panic!("oh no");
    unreachable!("never happens");
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(report.statistics.panic_sites >= 2);
}

#[test]
fn test_c_analyzer_detects_malloc() {
    let dir = TempDir::new().unwrap();
    let content = r#"
#include <stdlib.h>

int main() {
    int* ptr = malloc(sizeof(int) * 100);
    int* ptr2 = calloc(50, sizeof(int));
    return 0;
}
"#;
    let file = create_test_file(&dir, "test.c", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert_eq!(report.language, Language::C);
    assert!(report.statistics.allocation_sites >= 2);
}

#[test]
fn test_c_analyzer_detects_unchecked_malloc() {
    let dir = TempDir::new().unwrap();
    let content = r#"
#include <stdlib.h>

int main() {
    int* ptr = malloc(100);
    *ptr = 42;  // Unchecked!
}
"#;
    let file = create_test_file(&dir, "test.c", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    let unchecked = report
        .weak_points
        .iter()
        .any(|wp| matches!(wp.category, WeakPointCategory::UncheckedAllocation));
    assert!(unchecked, "Should detect unchecked malloc");
}

#[test]
fn test_go_analyzer_detects_goroutines() {
    let dir = TempDir::new().unwrap();
    let content = r#"
package main

func main() {
    go func() { println("hello") }()
    go processData()
    go handleRequest()
}
"#;
    let file = create_test_file(&dir, "test.go", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert_eq!(report.language, Language::Go);
    assert!(report.statistics.threading_constructs >= 3);
}

#[test]
fn test_python_analyzer_detects_unbounded_loop() {
    let dir = TempDir::new().unwrap();
    let content = r#"
def main():
    while True:
        process()
"#;
    let file = create_test_file(&dir, "test.py", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert_eq!(report.language, Language::Python);
    let unbounded = report
        .weak_points
        .iter()
        .any(|wp| matches!(wp.category, WeakPointCategory::UnboundedLoop));
    assert!(unbounded, "Should detect unbounded loop");
}

#[test]
fn test_generic_analyzer_basic_patterns() {
    let dir = TempDir::new().unwrap();
    let content = r#"
// Unknown language
function main() {
    let x = alloc(100);
    open("file.txt");
    thread.start();
}
"#;
    let file = create_test_file(&dir, "test.unknown", content);

    // Generic analyzer should still work, but language will be Unknown
    // and we just check it doesn't crash
    let _ = assail::analyze(&file);
}

#[test]
fn test_framework_detection_webserver() {
    // Framework detection for Rust relies on Cargo.toml, so we create a directory
    // with both a source file and a manifest declaring the dependency.
    let dir = TempDir::new().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("main.rs"),
        "use actix_web::{web, App, HttpServer};\nfn main() {}\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\n[dependencies]\nactix-web = \"4\"\n",
    )
    .unwrap();
    let report = assail::analyze(dir.path()).expect("analysis should succeed");

    assert!(
        report.frameworks.contains(&Framework::WebServer),
        "expected WebServer from Cargo.toml actix-web dep, got {:?}",
        report.frameworks
    );
}

#[test]
fn test_framework_detection_database() {
    let dir = TempDir::new().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("main.rs"),
        "use diesel::prelude::*;\nfn main() {}\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\n[dependencies]\ndiesel = \"2\"\n",
    )
    .unwrap();
    let report = assail::analyze(dir.path()).expect("analysis should succeed");

    assert!(
        report.frameworks.contains(&Framework::Database),
        "expected Database from Cargo.toml diesel dep, got {:?}",
        report.frameworks
    );
}

#[test]
fn test_per_file_stats_populated() {
    let dir = TempDir::new().unwrap();
    let content = r#"
fn main() {
    let x = Some(5).unwrap();
    unsafe { std::ptr::null::<i32>() };
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        !report.file_statistics.is_empty(),
        "Should have file statistics"
    );
    let stats = &report.file_statistics[0];
    assert!(stats.file_path.contains("test.rs"));
    assert!(stats.lines > 0);
}
