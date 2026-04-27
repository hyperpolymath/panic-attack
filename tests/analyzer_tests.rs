// SPDX-License-Identifier: PMPL-1.0-or-later

//! Unit tests for language-specific analyzers.
//!
//! All tests are panic-free: helpers return `Result`, test functions use
//! `-> Result<(), Box<dyn std::error::Error>>` and propagate errors with `?`.

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use tempfile::TempDir;

/// Write `content` to `dir/name` and return the full path.
///
/// Returns an error rather than panicking so test failures report the
/// actual I/O reason instead of a bare panic.
fn write_test_file(
    dir: &TempDir,
    name: &str,
    content: &str,
) -> std::io::Result<std::path::PathBuf> {
    let path = dir.path().join(name);
    fs::write(&path, content)?;
    Ok(path)
}

#[test]
fn test_rust_analyzer_detects_unsafe() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
fn main() {
    unsafe {
        let x = std::ptr::null::<i32>();
    }
    unsafe fn dangerous() {}
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert_eq!(report.language, Language::Rust);
    assert!(report.statistics.unsafe_blocks >= 2);
    assert!(!report.weak_points.is_empty());
    Ok(())
}

#[test]
fn test_rust_analyzer_detects_unwraps() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
fn main() {
    let x = Some(5).unwrap();
    let y = Ok::<i32, ()>(10).expect("should work");
    let z = vec![1,2,3].get(0).unwrap();
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(report.statistics.unwrap_calls >= 3);
    Ok(())
}

#[test]
fn test_rust_analyzer_detects_panics() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
fn main() {
    panic!("oh no");
    unreachable!("never happens");
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(report.statistics.panic_sites >= 2);
    Ok(())
}

#[test]
fn test_c_analyzer_detects_malloc() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.c",
        r#"
#include <stdlib.h>

int main() {
    int* ptr = malloc(sizeof(int) * 100);
    int* ptr2 = calloc(50, sizeof(int));
    return 0;
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert_eq!(report.language, Language::C);
    assert!(report.statistics.allocation_sites >= 2);
    Ok(())
}

#[test]
fn test_c_analyzer_detects_unchecked_malloc() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.c",
        r#"
#include <stdlib.h>

int main() {
    int* ptr = malloc(100);
    *ptr = 42;  // Unchecked!
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    let unchecked = report
        .weak_points
        .iter()
        .any(|wp| matches!(wp.category, WeakPointCategory::UncheckedAllocation));
    assert!(unchecked, "Should detect unchecked malloc");
    Ok(())
}

#[test]
fn test_go_analyzer_detects_goroutines() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.go",
        r#"
package main

func main() {
    go func() { println("hello") }()
    go processData()
    go handleRequest()
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert_eq!(report.language, Language::Go);
    assert!(report.statistics.threading_constructs >= 3);
    Ok(())
}

#[test]
fn test_python_analyzer_detects_unbounded_loop() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.py",
        r#"
def main():
    while True:
        process()
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert_eq!(report.language, Language::Python);
    let unbounded = report
        .weak_points
        .iter()
        .any(|wp| matches!(wp.category, WeakPointCategory::UnboundedLoop));
    assert!(unbounded, "Should detect unbounded loop");
    Ok(())
}

#[test]
fn test_generic_analyzer_basic_patterns() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.unknown",
        r#"
// Unknown language
function main() {
    let x = alloc(100);
    open("file.txt");
    thread.start();
}
"#,
    )?;
    // Generic analyzer should still work; we only check it doesn't crash
    let _ = assail::analyze(&file);
    Ok(())
}

#[test]
fn test_framework_detection_webserver() -> Result<(), Box<dyn std::error::Error>> {
    // Framework detection for Rust uses Cargo.toml, so we need a directory
    // with both a source file and a manifest declaring the dependency.
    let dir = TempDir::new()?;
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(
        src_dir.join("main.rs"),
        "use actix_web::{web, App, HttpServer};\nfn main() {}\n",
    )?;
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\n[dependencies]\nactix-web = \"4\"\n",
    )?;
    let report = assail::analyze(dir.path())?;

    assert!(
        report.frameworks.contains(&Framework::WebServer),
        "expected WebServer from Cargo.toml actix-web dep, got {:?}",
        report.frameworks
    );
    Ok(())
}

#[test]
fn test_framework_detection_database() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(
        src_dir.join("main.rs"),
        "use diesel::prelude::*;\nfn main() {}\n",
    )?;
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\n[dependencies]\ndiesel = \"2\"\n",
    )?;
    let report = assail::analyze(dir.path())?;

    assert!(
        report.frameworks.contains(&Framework::Database),
        "expected Database from Cargo.toml diesel dep, got {:?}",
        report.frameworks
    );
    Ok(())
}

#[test]
fn test_todo_in_string_literal_does_not_trigger_unchecked_error(
) -> Result<(), Box<dyn std::error::Error>> {
    // Regression: parser.rs had 155 `.expect("TODO: handle error")` calls.
    // The old detector counted `content.matches("TODO")` on raw bytes, so each
    // string literal incremented the TODO counter. Stub code with `.expect("TODO: …")`
    // must not fire UncheckedError.
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "stubby.rs",
        r#"
pub fn parse_stubbed(input: &str) -> String {
    let first = input.split(',').next().expect("TODO: handle error");
    let second = input.split('.').next().expect("TODO: handle error");
    let third = input.split('/').next().expect("TODO: handle error");
    let fourth = input.split(':').next().expect("TODO: handle error");
    let fifth = input.split(';').next().expect("TODO: handle error");
    let sixth = input.split('-').next().expect("TODO: handle error");
    let seventh = input.split('_').next().expect("TODO: handle error");
    let eighth = input.split('+').next().expect("TODO: handle error");
    let ninth = input.split('*').next().expect("TODO: handle error");
    let tenth = input.split('!').next().expect("TODO: handle error");
    let eleventh = input.split('?').next().expect("TODO: handle error");
    format!("{}{}{}{}{}{}{}{}{}{}{}",
        first, second, third, fourth, fifth, sixth,
        seventh, eighth, ninth, tenth, eleventh)
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    let unchecked: Vec<_> = report
        .weak_points
        .iter()
        .filter(|wp| wp.category == WeakPointCategory::UncheckedError)
        .collect();

    assert!(
        unchecked.is_empty(),
        "TODO inside .expect() string literals must not count as \
         UncheckedError markers: got {:?}",
        unchecked
    );
    Ok(())
}

#[test]
fn test_real_todo_comments_still_detected() -> Result<(), Box<dyn std::error::Error>> {
    // Sanity: actual `// TODO` comments above the 11-item threshold must still fire.
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "debt.rs",
        r#"
// TODO: implement proper error handling
// TODO: add tests for edge cases
// TODO: optimise hot path
// TODO: document invariants
// FIXME: this leaks memory on panic
// FIXME: race condition in iterator
// FIXME: buffer overflow possible
// HACK: using unsafe pointer cast as workaround
// HACK: bypassing type check with transmute
// HACK: relying on undocumented behaviour
// XXX: this block needs review
// XXX: performance critical but correctness unclear
pub fn stub() -> i32 { 42 }
"#,
    )?;
    let report = assail::analyze(&file)?;

    let unchecked: Vec<_> = report
        .weak_points
        .iter()
        .filter(|wp| wp.category == WeakPointCategory::UncheckedError)
        .collect();

    assert!(
        !unchecked.is_empty(),
        "real // TODO / // FIXME / // HACK / // XXX comments above \
         the threshold should still fire the detector"
    );
    Ok(())
}

#[test]
fn test_per_file_stats_populated() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let file = write_test_file(
        &dir,
        "test.rs",
        r#"
fn main() {
    let x = Some(5).unwrap();
    unsafe { std::ptr::null::<i32>() };
}
"#,
    )?;
    let report = assail::analyze(&file)?;

    assert!(
        !report.file_statistics.is_empty(),
        "Should have file statistics"
    );
    let stats = &report.file_statistics[0];
    assert!(stats.file_path.contains("test.rs"));
    assert!(stats.lines > 0);
    Ok(())
}
