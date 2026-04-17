// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Benchmarks for panic-attack scan performance.
//!
//! Measures: language detection, pattern matching, full analysis pipeline.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use panic_attack::types::Language;

/// Benchmark language detection from file extension
fn bench_language_detect(c: &mut Criterion) {
    let extensions = vec![
        "main.rs",
        "lib.rs",
        "app.py",
        "index.js",
        "server.ex",
        "types.idr",
        "Main.hs",
        "config.ncl",
        "build.zig",
        "test.gleam",
        "script.sh",
        "model.jl",
        "style.css",
        "unknown.xyz",
        "Component.res",
        "parser.ml",
        "proof.lean",
        "rules.lgt",
    ];

    c.bench_function("language_detect_18_files", |b| {
        b.iter(|| {
            for ext in &extensions {
                black_box(Language::detect(ext));
            }
        })
    });
}

/// Benchmark language family classification
fn bench_language_family(c: &mut Criterion) {
    let languages = vec![
        Language::Rust,
        Language::Elixir,
        Language::Gleam,
        Language::ReScript,
        Language::Idris,
        Language::Zig,
        Language::Haskell,
        Language::Python,
        Language::JavaScript,
        Language::Shell,
        Language::Julia,
        Language::Nickel,
    ];

    c.bench_function("language_family_12_langs", |b| {
        b.iter(|| {
            for lang in &languages {
                black_box(lang.family());
            }
        })
    });
}

/// Benchmark assail analysis on the panic-attacker source itself (dogfooding)
fn bench_self_scan(c: &mut Criterion) {
    // Only run if the src directory exists (it should, we're in the repo)
    let src_path = std::path::Path::new("src");
    if !src_path.exists() {
        return;
    }

    c.bench_function("assail_self_scan", |b| {
        b.iter(|| {
            let _ = black_box(panic_attack::assail::analyze("src"));
        })
    });
}

/// Benchmark the UnboundedAllocation heuristic end-to-end on a single
/// file. After the substring -> word-boundary regex refactor (Task #25),
/// this gives a per-file analysis number for tight dev loops — smaller
/// than the full `assail_self_scan` which walks all of src/.
///
/// Uses `tempfile` to write a synthetic .rs file and analyse its
/// parent directory; the per-iter overhead includes one stat() and
/// one file open, which is the realistic cost path.
fn bench_unbounded_allocation_detector(c: &mut Criterion) {
    use std::io::Write;

    // Synthetic source that exercises the detector in both directions:
    // contains tokio's `unbounded_channel` (must NOT fire — word-boundary),
    // the detector's own `has_unbounded_allocations` identifier
    // (must NOT fire — trailing `_`), and a bounded `.take(LIMIT)` read.
    let clean_rust_source = r#"
use std::io::Read;
use tokio::sync::mpsc;

const READ_LIMIT: u64 = 64 * 1024 * 1024;

pub fn make_channel() -> mpsc::UnboundedSender<u8> {
    let (tx, _) = mpsc::unbounded_channel();
    tx
}

pub fn load(path: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::fs::File::open(path)?.take(READ_LIMIT).read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn analyze(body: &str) -> bool {
    let has_unbounded_allocations = body.contains("x");
    let unbounded_vec_patterns = body.len();
    has_unbounded_allocations && unbounded_vec_patterns > 0
}
"#;

    let clean_dir = tempfile::tempdir().expect("tempdir");
    let clean_file = clean_dir.path().join("clean.rs");
    std::fs::File::create(&clean_file)
        .unwrap()
        .write_all(clean_rust_source.as_bytes())
        .unwrap();

    c.bench_function("unbounded_detector_clean_file", |b| {
        b.iter(|| {
            let _ = black_box(panic_attack::assail::analyze(clean_dir.path()));
        })
    });

    // Dirty source: bare `unbounded()` fn + unbounded fs::read_to_string.
    // Detector SHOULD fire. Positive-signal path.
    let dirty_rust_source = r#"
pub fn unbounded() -> Vec<u8> {
    Vec::new()
}

pub fn slurp(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}
"#;

    let dirty_dir = tempfile::tempdir().expect("tempdir");
    let dirty_file = dirty_dir.path().join("dirty.rs");
    std::fs::File::create(&dirty_file)
        .unwrap()
        .write_all(dirty_rust_source.as_bytes())
        .unwrap();

    c.bench_function("unbounded_detector_dirty_file", |b| {
        b.iter(|| {
            let _ = black_box(panic_attack::assail::analyze(dirty_dir.path()));
        })
    });
}

/// Benchmark taint analysis engine
fn bench_taint_analysis(c: &mut Criterion) {
    use panic_attack::kanren::core::FactDB;
    use panic_attack::kanren::taint::TaintAnalyzer;

    c.bench_function("taint_query_flows_empty", |b| {
        let db = FactDB::new();
        b.iter(|| {
            let _flows = black_box(TaintAnalyzer::query_flows(&db));
        })
    });
}

/// Benchmark rule evaluation throughput
fn bench_rule_evaluation(c: &mut Criterion) {
    let languages = vec![
        panic_attack::types::Language::Rust,
        panic_attack::types::Language::Python,
        panic_attack::types::Language::JavaScript,
        panic_attack::types::Language::Go,
    ];

    c.bench_function("rule_eval_4_languages", |b| {
        b.iter(|| {
            for lang in &languages {
                black_box(lang.family());
            }
        })
    });
}

/// Benchmark weak point location extraction
fn bench_location_extraction(c: &mut Criterion) {
    let weak_points = vec![
        panic_attack::types::WeakPoint {
            category: panic_attack::types::WeakPointCategory::UnsafeCode,
            severity: panic_attack::types::Severity::High,
            location: Some("test.rs:10".to_string()),
            file: None,
            line: None,
            description: "test".to_string(),
            recommended_attack: vec![],
            suppressed: false,
        };
        100
    ];

    c.bench_function("extract_locations_100_points", |b| {
        b.iter(|| {
            for wp in &weak_points {
                let _ = black_box(&wp.location);
            }
        })
    });
}

/// Benchmark statistics calculation
fn bench_statistics_calculation(c: &mut Criterion) {
    c.bench_function("stats_field_access", |b| {
        let stats = panic_attack::types::ProgramStatistics {
            total_lines: 10000,
            unsafe_blocks: 5,
            panic_sites: 0,
            unwrap_calls: 50,
            allocation_sites: 12,
            io_operations: 4,
            threading_constructs: 3,
        };

        b.iter(|| {
            let _ = black_box(stats.total_lines);
            let _ = black_box(stats.unwrap_calls);
            let _ = black_box(stats.unsafe_blocks);
            let _ = black_box(stats.panic_sites);
        })
    });
}

criterion_group!(
    benches,
    bench_language_detect,
    bench_language_family,
    bench_self_scan,
    bench_unbounded_allocation_detector,
    bench_taint_analysis,
    bench_rule_evaluation,
    bench_location_extraction,
    bench_statistics_calculation
);
criterion_main!(benches);
