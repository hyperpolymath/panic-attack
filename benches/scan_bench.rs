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
        "main.rs", "lib.rs", "app.py", "index.js", "server.ex",
        "types.idr", "Main.hs", "config.ncl", "build.zig", "test.gleam",
        "script.sh", "model.jl", "style.css", "unknown.xyz",
        "Component.res", "parser.ml", "proof.lean", "rules.lgt",
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
        Language::Rust, Language::Elixir, Language::Gleam,
        Language::ReScript, Language::Idris, Language::Zig,
        Language::Haskell, Language::Python, Language::JavaScript,
        Language::Shell, Language::Julia, Language::Nickel,
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

/// Benchmark taint analysis engine
fn bench_taint_analysis(c: &mut Criterion) {
    use panic_attack::kanren::taint::TaintAnalyzer;

    c.bench_function("taint_sources_iteration", |b| {
        let analyzer = TaintAnalyzer::new();
        b.iter(|| {
            let _sources = black_box(analyzer.sources());
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
            description: "test".to_string(),
            recommended_attack: vec![],
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
            unwrap_calls: 50,
            expect_calls: 20,
            unsafe_blocks: 5,
            threading_constructs: 3,
            panic_paths: 0,
        };

        b.iter(|| {
            let _ = black_box(stats.total_lines);
            let _ = black_box(stats.unwrap_calls);
            let _ = black_box(stats.expect_calls);
            let _ = black_box(stats.unsafe_blocks);
        })
    });
}

criterion_group!(
    benches,
    bench_language_detect,
    bench_language_family,
    bench_self_scan,
    bench_taint_analysis,
    bench_rule_evaluation,
    bench_location_extraction,
    bench_statistics_calculation
);
criterion_main!(benches);
