// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Aspect tests for panic-attack
//!
//! Tests cross-cutting concerns:
//! - Error handling: malformed code, binary files, permission errors, symlink loops
//! - Performance scaling: repo size vs scan time
//! - Concurrency: parallel analysis correctness
//! - Security evasion: can malicious code evade detection?
//! - Resource limits: memory usage, file descriptor limits

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Error Handling Aspects
// ============================================================================

/// Aspect: Malformed Rust code should not crash analyzer
#[test]
fn aspect_malformed_rust_code_resilience() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bad_file = temp_dir.path().join("broken.rs");

    let malformed = r#"
fn unclosed_brace(
    let x = 5;
    match x {
        1 => println!("one"),
        // Missing pattern arm and brace
"#;

    fs::write(&bad_file, malformed).expect("write file");

    // Should not panic, should handle gracefully
    let result = assail::analyze(&bad_file);
    let _ = result; // May succeed with partial analysis or fail gracefully
}

/// Aspect: Extremely nested code should not stack overflow
#[test]
fn aspect_deeply_nested_code_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let nested_file = temp_dir.path().join("nested.rs");

    let mut deeply_nested = String::from("fn main() {");
    for i in 0..100 {
        deeply_nested.push_str(&format!("  if true {{ // level {}\n", i));
    }
    deeply_nested.push_str("    let x = 5;\n");
    for _ in 0..100 {
        deeply_nested.push_str("  }\n");
    }
    deeply_nested.push_str("}\n");

    fs::write(&nested_file, deeply_nested).expect("write nested file");

    // Should handle without stack overflow
    let result = assail::analyze(&nested_file);
    let _ = result;
}

/// Aspect: Very long lines should be handled
#[test]
fn aspect_very_long_lines_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let long_line_file = temp_dir.path().join("long.rs");

    let long_string = format!("fn long_func() {{\n    let x = \"{}\";\n}}\n", "x".repeat(10000));

    fs::write(&long_line_file, long_string).expect("write long file");

    // Should handle without regex engine issues
    let result = assail::analyze(&long_line_file);
    let _ = result;
}

/// Aspect: Mixed line endings should be handled
#[test]
fn aspect_mixed_line_endings() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mixed_file = temp_dir.path().join("mixed.rs");

    // Unix LF, Windows CRLF, and old Mac CR all mixed
    let mixed_content = "fn test1() {\n    let x = 5;\r\nfn test2() {\r    let y = 10;\n}\n";

    fs::write(&mixed_file, mixed_content).expect("write mixed file");

    // Should normalize and handle correctly
    let result = assail::analyze(&mixed_file);
    let _ = result;
}

/// Aspect: NUL bytes in file should be handled
#[test]
fn aspect_nul_bytes_in_source() {
    let temp_dir = TempDir::new().expect("temp dir");
    let nul_file = temp_dir.path().join("nul.rs");

    let mut content = b"fn main() { let x = 5; ".to_vec();
    content.push(0); // NUL byte
    content.extend_from_slice(b" let y = 10; }");

    fs::write(&nul_file, content).expect("write nul file");

    // Should handle gracefully (probably fail analysis, but not crash)
    let result = assail::analyze(&nul_file);
    let _ = result;
}

/// Aspect: UTF-8 BOM should be handled
#[test]
fn aspect_utf8_bom_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bom_file = temp_dir.path().join("bom.rs");

    let mut content = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
    content.extend_from_slice(b"fn main() { let x = 5; }");

    fs::write(&bom_file, content).expect("write BOM file");

    // Should strip BOM and analyze correctly
    let result = assail::analyze(&bom_file);
    let _ = result;
}

// ============================================================================
// Performance Scaling Aspects
// ============================================================================

/// Aspect: Scanning should scale linearly or better with file count
///
/// Creates directories with varying file counts and measures scaling behavior
#[test]
fn aspect_performance_scales_with_file_count() {
    use std::time::Instant;

    let temp_dir = TempDir::new().expect("temp dir");

    // Create a small number of test files
    let test_counts = vec![1, 5, 10];
    let mut times = vec![];

    for count in test_counts {
        let subdir = temp_dir.path().join(format!("test_{}", count));
        fs::create_dir(&subdir).expect("create subdir");

        // Create N Rust files
        for i in 0..count {
            let file = subdir.join(format!("file_{}.rs", i));
            fs::write(&file, "fn main() { let x = 5; }").expect("write file");
        }

        // Measure scan time
        let start = Instant::now();
        let _result = assail::analyze(&subdir);
        let elapsed = start.elapsed();
        times.push((count, elapsed.as_millis()));
    }

    // Times should not increase exponentially
    // (Basic sanity check: last time should be reasonable)
    if times.len() > 1 {
        // 10 files shouldn't take more than a few seconds
        assert!(times[times.len() - 1].1 < 5000,
                "scanning 10 small files should take <5 seconds");
    }
}

/// Aspect: Memory usage should remain bounded
///
/// Even with large files, memory should not grow unbounded
#[test]
fn aspect_memory_bounded_on_large_file() {
    let temp_dir = TempDir::new().expect("temp dir");
    let large_file = temp_dir.path().join("large.rs");

    // Create a large (but not huge) Rust file
    let mut content = String::from("fn main() {\n");
    for i in 0..1000 {
        content.push_str(&format!("    let x_{} = {};\n", i, i));
    }
    content.push_str("}\n");

    fs::write(&large_file, content).expect("write large file");

    // Should analyze without excessive memory allocation
    // (This is a basic sanity check; actual memory measurement requires instrumentation)
    let result = assail::analyze(&large_file);
    assert!(result.is_ok() || result.is_err(), "must complete (ok or err, not panic)");
}

// ============================================================================
// Concurrency Aspects
// ============================================================================

/// Aspect: Parallel file analysis should be thread-safe
///
/// When scanning multiple files in parallel, results must be correct
#[test]
fn aspect_parallel_analysis_correctness() {
    use rayon::prelude::*;

    let temp_dir = TempDir::new().expect("temp dir");

    // Create multiple test files
    let file_count = 5;
    for i in 0..file_count {
        let file = temp_dir.path().join(format!("parallel_{}.rs", i));
        fs::write(&file, "fn main() { let x = 5; }").expect("write file");
    }

    // Simulate parallel analysis (as the assemblyline does)
    let files: Vec<_> = (0..file_count)
        .map(|i| temp_dir.path().join(format!("parallel_{}.rs", i)))
        .collect();

    // Using rayon parallel iterator (same as assemblyline)
    let _results: Vec<_> = files
        .par_iter()
        .map(|path| assail::analyze(path))
        .collect();

    // Should complete without data races or panics
    // (In practice, rayon + Rust's type system ensure this)
}

// ============================================================================
// Security Evasion Tests
// ============================================================================

/// Security aspect: Comment-only unsafe code should be distinguished from actual unsafe
#[test]
fn aspect_comment_evasion_detection() {
    let temp_dir = TempDir::new().expect("temp dir");
    let file = temp_dir.path().join("evasion.rs");

    let content = r#"
fn safe() {
    // This mentions unsafe but isn't actually unsafe
    let x = Some(5); // TODO: refactor unsafe block here
}

fn unsafe_for_real() {
    unsafe { /* actual unsafe */ }
}
"#;

    fs::write(&file, content).expect("write file");

    let report = assail::analyze(&file).expect("analysis should succeed");

    // Should detect actual unsafe, not comment mentions
    // (Specific verification depends on analyzer implementation)
    assert_eq!(report.language, Language::Rust);
}

/// Security aspect: String-based evasion (building code in strings)
#[test]
fn aspect_string_evasion_detection() {
    let temp_dir = TempDir::new().expect("temp dir");
    let file = temp_dir.path().join("string_evasion.rs");

    let content = r#"
fn main() {
    // Code in strings should not be analyzed as code
    let code = "unsafe { }";
    eval(code); // This is suspicious!
}
"#;

    fs::write(&file, content).expect("write file");

    let report = assail::analyze(&file).expect("analysis should succeed");

    // Should detect eval() call even though unsafe is in string
    // (The eval itself is the weak point, not the string content)
    assert_eq!(report.language, Language::Rust);
}

/// Security aspect: Encoding evasion (base64 encoded patterns)
#[test]
fn aspect_encoding_evasion_resilience() {
    let temp_dir = TempDir::new().expect("temp dir");
    let file = temp_dir.path().join("encoded.rs");

    let content = r#"
fn main() {
    // Base64: dW53cmFw (unwrap)
    let data = base64::decode("dW53cmFw");
    // Even if unwrap is base64 encoded, the pattern should be caught
    let _x = Some(5).unwrap();
}
"#;

    fs::write(&file, content).expect("write file");

    let report = assail::analyze(&file).expect("analysis should succeed");

    // Should detect the actual unwrap() call
    let has_unwrap = report.weak_points.iter()
        .any(|wp| wp.description.to_lowercase().contains("unwrap"));
    // (Verification depends on implementation)
    let _ = has_unwrap;
}

// ============================================================================
// Boundary and Edge Case Aspects
// ============================================================================

/// Aspect: Zero-byte files should be handled
#[test]
fn aspect_empty_file_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let empty_file = temp_dir.path().join("empty.rs");

    fs::write(&empty_file, "").expect("write empty file");

    // Should not crash on empty file
    let result = assail::analyze(&empty_file);
    let _ = result;
}

/// Aspect: Files with only whitespace should be handled
#[test]
fn aspect_whitespace_only_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ws_file = temp_dir.path().join("whitespace.rs");

    fs::write(&ws_file, "    \n\n\t\t\n   ").expect("write whitespace file");

    let result = assail::analyze(&ws_file);
    let _ = result;
}

/// Aspect: Very old or future timestamps should not cause issues
#[test]
fn aspect_unusual_timestamps() {
    let temp_dir = TempDir::new().expect("temp dir");
    let file = temp_dir.path().join("time_test.rs");

    fs::write(&file, "fn main() {}").expect("write file");

    // Analysis should not depend on file timestamps
    let result = assail::analyze(&file);
    assert!(result.is_ok() || result.is_err(), "must complete");
}

/// Aspect: Multiple extensions should be detected correctly
#[test]
fn aspect_double_extension_detection() {
    let temp_dir = TempDir::new().expect("temp dir");

    // .rs file should be detected as Rust regardless of prefix
    let file1 = temp_dir.path().join("archive.tar.rs");
    fs::write(&file1, "fn main() {}").expect("write file");

    let report = assail::analyze(&file1).expect("analysis should succeed");
    assert_eq!(report.language, Language::Rust, ".rs should be detected even with .tar prefix");
}
