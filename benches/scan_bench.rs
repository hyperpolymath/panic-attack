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

criterion_group!(benches, bench_language_detect, bench_language_family, bench_self_scan);
criterion_main!(benches);
