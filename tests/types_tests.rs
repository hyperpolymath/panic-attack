// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

//! Unit tests for core types — Language detection, family classification,
//! WeakPointCategory coverage, and serialization contracts.

use panic_attack::types::*;

// ─── Language Detection (47 languages) ────────────────────────────────────

#[test]
fn language_detect_rust() {
    assert_eq!(Language::detect("src/main.rs"), Language::Rust);
    assert_eq!(Language::detect("lib.rs"), Language::Rust);
}

#[test]
fn language_detect_c_family() {
    assert_eq!(Language::detect("foo.c"), Language::C);
    assert_eq!(Language::detect("foo.h"), Language::C);
    assert_eq!(Language::detect("bar.cpp"), Language::Cpp);
    assert_eq!(Language::detect("bar.hpp"), Language::Cpp);
}

#[test]
fn language_detect_beam_family() {
    assert_eq!(Language::detect("server.ex"), Language::Elixir);
    assert_eq!(Language::detect("test.exs"), Language::Elixir);
    assert_eq!(Language::detect("gen.erl"), Language::Erlang);
    assert_eq!(Language::detect("app.gleam"), Language::Gleam);
}

#[test]
fn language_detect_ml_family() {
    assert_eq!(Language::detect("Component.res"), Language::ReScript);
    assert_eq!(Language::detect("types.resi"), Language::ReScript);
    assert_eq!(Language::detect("parser.ml"), Language::OCaml);
    assert_eq!(Language::detect("sig.mli"), Language::OCaml);
    assert_eq!(Language::detect("main.sml"), Language::StandardML);
}

#[test]
fn language_detect_proof_assistants() {
    assert_eq!(Language::detect("Types.idr"), Language::Idris);
    assert_eq!(Language::detect("proof.lean"), Language::Lean);
    assert_eq!(Language::detect("module.agda"), Language::Agda);
}

#[test]
fn language_detect_logic_programming() {
    assert_eq!(Language::detect("rules.lgt"), Language::Logtalk);
    assert_eq!(Language::detect("facts.pl"), Language::Prolog);
    assert_eq!(Language::detect("query.dl"), Language::Datalog);
}

#[test]
fn language_detect_systems_languages() {
    assert_eq!(Language::detect("build.zig"), Language::Zig);
    assert_eq!(Language::detect("main.adb"), Language::Ada);
    assert_eq!(Language::detect("spec.ads"), Language::Ada);
    assert_eq!(Language::detect("app.odin"), Language::Odin);
    assert_eq!(Language::detect("config.nim"), Language::Nim);
    assert_eq!(Language::detect("actor.pony"), Language::Pony);
}

#[test]
fn language_detect_config_languages() {
    assert_eq!(Language::detect("config.ncl"), Language::Nickel);
    assert_eq!(Language::detect("flake.nix"), Language::Nix);
}

#[test]
fn language_detect_scripting() {
    assert_eq!(Language::detect("script.sh"), Language::Shell);
    assert_eq!(Language::detect("deploy.bash"), Language::Shell);
    assert_eq!(Language::detect("model.jl"), Language::Julia);
    assert_eq!(Language::detect("plugin.lua"), Language::Lua);
}

#[test]
fn language_detect_nextgen_dsls() {
    assert_eq!(Language::detect("module.ecl"), Language::Eclexia);
    assert_eq!(Language::detect("linear.eph"), Language::Ephapax);
    assert_eq!(Language::detect("game.bet"), Language::BetLang);
    assert_eq!(Language::detect("script.woke"), Language::WokeLang);
    assert_eq!(Language::detect("query.vql"), Language::VQL);
    assert_eq!(Language::detect("types.aff"), Language::AffineScript);
}

#[test]
fn language_detect_javascript_variants() {
    // TS/TSX/JSX all map to JavaScript (ReScript is the replacement)
    assert_eq!(Language::detect("app.js"), Language::JavaScript);
    assert_eq!(Language::detect("module.mjs"), Language::JavaScript);
    assert_eq!(Language::detect("legacy.ts"), Language::JavaScript);
    assert_eq!(Language::detect("component.tsx"), Language::JavaScript);
    assert_eq!(Language::detect("widget.jsx"), Language::JavaScript);
}

#[test]
fn language_detect_unknown() {
    assert_eq!(Language::detect("readme.md"), Language::Unknown);
    assert_eq!(Language::detect("data.csv"), Language::Unknown);
    assert_eq!(Language::detect("image.png"), Language::Unknown);
    assert_eq!(Language::detect("noext"), Language::Unknown);
}

// ─── Language Family Classification ───────────────────────────────────────

#[test]
fn language_family_beam() {
    assert_eq!(Language::Elixir.family(), "beam");
    assert_eq!(Language::Erlang.family(), "beam");
    assert_eq!(Language::Gleam.family(), "beam");
}

#[test]
fn language_family_ml() {
    assert_eq!(Language::ReScript.family(), "ml");
    assert_eq!(Language::OCaml.family(), "ml");
    assert_eq!(Language::StandardML.family(), "ml");
}

#[test]
fn language_family_proof() {
    assert_eq!(Language::Idris.family(), "proof");
    assert_eq!(Language::Lean.family(), "proof");
    assert_eq!(Language::Agda.family(), "proof");
}

#[test]
fn language_family_systems() {
    assert_eq!(Language::Zig.family(), "systems");
    assert_eq!(Language::Ada.family(), "systems");
    assert_eq!(Language::Nim.family(), "systems");
}

#[test]
fn language_family_config() {
    assert_eq!(Language::Nickel.family(), "config");
    assert_eq!(Language::Nix.family(), "config");
}

// ─── Serialization Contracts ──────────────────────────────────────────────

#[test]
fn language_serializes_lowercase() {
    let json = serde_json::to_string(&Language::Rust).unwrap();
    assert_eq!(json, "\"rust\"");

    let json = serde_json::to_string(&Language::Elixir).unwrap();
    assert_eq!(json, "\"elixir\"");

    let json = serde_json::to_string(&Language::ReScript).unwrap();
    assert_eq!(json, "\"rescript\"");
}

#[test]
fn language_deserializes_from_lowercase() {
    let lang: Language = serde_json::from_str("\"rust\"").unwrap();
    assert_eq!(lang, Language::Rust);

    let lang: Language = serde_json::from_str("\"idris\"").unwrap();
    assert_eq!(lang, Language::Idris);
}

#[test]
fn language_roundtrip_serde() {
    let languages = vec![
        Language::Rust, Language::Elixir, Language::Gleam,
        Language::ReScript, Language::Idris, Language::Zig,
        Language::Haskell, Language::Nickel, Language::Ephapax,
    ];

    for lang in languages {
        let json = serde_json::to_string(&lang).unwrap();
        let deserialized: Language = serde_json::from_str(&json).unwrap();
        assert_eq!(lang, deserialized, "Roundtrip failed for {:?}", lang);
    }
}

// ─── WeakPointCategory Coverage ───────────────────────────────────────────

#[test]
fn weak_point_category_serializes() {
    let json = serde_json::to_string(&WeakPointCategory::UnsafeCode).unwrap();
    assert!(!json.is_empty());

    let json = serde_json::to_string(&WeakPointCategory::PanicPath).unwrap();
    assert!(!json.is_empty());
}

// ─── AssailReport Structure ───────────────────────────────────────────────

#[test]
fn assail_report_serializes_to_json() {
    let report = AssailReport {
        program_path: std::path::PathBuf::from("test/target"),
        language: Language::Rust,
        frameworks: vec![],
        weak_points: vec![],
        statistics: Default::default(),
        file_statistics: vec![],
        recommended_attacks: vec![],
        dependency_graph: Default::default(),
        taint_matrix: Default::default(),
        migration_metrics: None,
    };

    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"language\":\"rust\""));

    // Verify it can be deserialized back
    let _: AssailReport = serde_json::from_str(&json).unwrap();
}
