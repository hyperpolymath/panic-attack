// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Cross-language vulnerability analysis
//!
//! Detects security-relevant interactions between different programming
//! languages in polyglot codebases: FFI boundaries, message passing,
//! shared state, and serialization boundaries.

use crate::kanren::core::{FactDB, LogicFact, LogicRule, RuleMetadata, Term};
use crate::types::*;

/// Mechanism by which languages interact
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionMechanism {
    /// C FFI (Rust→C, Zig→C, Ada→C, etc.)
    CFfi,
    /// NIFs/Ports in BEAM (Elixir/Erlang calling Rust/C)
    BeamNif,
    /// Erlang Port (spawning external process)
    BeamPort,
    /// JavaScript FFI (ReScript→JS, PureScript→JS)
    JsFfi,
    /// Subprocess spawning (System.cmd, Process.spawn)
    Subprocess,
    /// Shared file (JSON, YAML, config)
    SharedFile,
    /// Network protocol (HTTP API, gRPC, socket)
    NetworkProtocol,
    /// Stdin/Stdout pipe (Julia bridge, Elixir Port)
    StdioPipe,
    /// WASM module boundary
    WasmBoundary,
}

/// A detected cross-language interaction
#[derive(Debug, Clone)]
pub struct CrossLangInteraction {
    pub caller_file: String,
    pub caller_lang: Language,
    pub callee_file: String,
    pub callee_lang: Language,
    pub mechanism: InteractionMechanism,
    pub risk_score: f64,
}

/// Analyzes cross-language vulnerability chains
pub struct CrossLangAnalyzer;

impl CrossLangAnalyzer {
    /// Extract cross-language interaction facts from file statistics and weak points
    pub fn extract_facts(db: &mut FactDB, report: &AssailReport) {
        // Index files by language
        let mut file_langs: Vec<(String, Language)> = Vec::new();
        for fs in &report.file_statistics {
            let lang = Language::detect(&fs.file_path);
            if lang != Language::Unknown {
                file_langs.push((fs.file_path.clone(), lang));

                // Assert file_lang fact
                db.assert_fact(LogicFact::new(
                    "file_lang",
                    vec![
                        Term::atom(&fs.file_path),
                        Term::atom(&format!("{:?}", lang)),
                    ],
                ));
            }
        }

        // Detect cross-language interactions from weak points
        for wp in &report.weak_points {
            let file = wp.location.as_deref().unwrap_or("unknown");
            let file_lang = Language::detect(file);

            match wp.category {
                WeakPointCategory::UnsafeFFI => {
                    // FFI implies crossing a language boundary
                    let mechanism = Self::infer_ffi_mechanism(file_lang);
                    db.assert_fact(LogicFact::new(
                        "cross_lang_call",
                        vec![
                            Term::atom(file),
                            Term::atom("foreign"),
                            Term::atom(&format!("{:?}", mechanism)),
                        ],
                    ));
                }
                WeakPointCategory::CommandInjection => {
                    // System.cmd / Port.open implies subprocess boundary
                    db.assert_fact(LogicFact::new(
                        "cross_lang_call",
                        vec![
                            Term::atom(file),
                            Term::atom("subprocess"),
                            Term::atom("Subprocess"),
                        ],
                    ));
                }
                WeakPointCategory::UnsafeDeserialization => {
                    // Deserialization can cross language boundaries via shared files
                    db.assert_fact(LogicFact::new(
                        "cross_lang_call",
                        vec![
                            Term::atom(file),
                            Term::atom("serialized_data"),
                            Term::atom("SharedFile"),
                        ],
                    ));
                }
                _ => {}
            }
        }

        // Detect language family boundaries in the project
        // Family boundaries are coarse but useful to prioritize polyglot trust edges.
        Self::detect_family_boundaries(db, &file_langs);
    }

    /// Infer the FFI mechanism based on the language
    fn infer_ffi_mechanism(lang: Language) -> InteractionMechanism {
        match lang {
            Language::Elixir | Language::Erlang => InteractionMechanism::BeamNif,
            Language::ReScript | Language::PureScript => InteractionMechanism::JsFfi,
            Language::Zig | Language::Ada | Language::Nim | Language::DLang => {
                InteractionMechanism::CFfi
            }
            Language::Rust | Language::C | Language::Cpp => InteractionMechanism::CFfi,
            _ => InteractionMechanism::Subprocess,
        }
    }

    /// Detect boundaries between language families in the project
    fn detect_family_boundaries(db: &mut FactDB, file_langs: &[(String, Language)]) {
        let mut families: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (_, lang) in file_langs {
            families.insert(lang.family());
        }

        // Emit pairwise family boundaries as undirected adjacency facts.
        let family_vec: Vec<&&str> = families.iter().collect();
        for i in 0..family_vec.len() {
            for j in (i + 1)..family_vec.len() {
                db.assert_fact(LogicFact::new(
                    "language_boundary",
                    vec![Term::atom(family_vec[i]), Term::atom(family_vec[j])],
                ));
            }
        }
    }

    /// Load cross-language vulnerability rules
    pub fn load_rules(db: &mut FactDB) {
        // Rule: ffi_risk(File, Mechanism) :-
        //   cross_lang_call(File, _, Mechanism),
        //   weak_point(UnsafeCode, File, _)
        db.add_rule(LogicRule::with_metadata(
            "ffi_risk".into(),
            LogicFact::new("ffi_risk", vec![Term::Var(400), Term::Var(402)]),
            vec![
                LogicFact::new(
                    "cross_lang_call",
                    vec![Term::Var(400), Term::Var(401), Term::Var(402)],
                ),
                LogicFact::new(
                    "weak_point",
                    vec![Term::atom("UnsafeCode"), Term::Var(400), Term::Var(403)],
                ),
            ],
            RuleMetadata::default(),
        ));

        // Rule: boundary_vuln(Family1, Family2) :-
        //   language_boundary(Family1, Family2),
        //   cross_lang_call(_, _, _)
        // (Signals that there is a vulnerability-relevant boundary)
        db.add_rule(LogicRule::with_metadata(
            "active_boundary".into(),
            LogicFact::new("active_boundary", vec![Term::Var(410), Term::Var(411)]),
            vec![
                LogicFact::new("language_boundary", vec![Term::Var(410), Term::Var(411)]),
                LogicFact::new(
                    "cross_lang_call",
                    vec![Term::Var(412), Term::Var(413), Term::Var(414)],
                ),
            ],
            RuleMetadata::default(),
        ));

        // Rule: serialization_risk(File) :-
        //   cross_lang_call(File, _, "SharedFile"),
        //   taint_source(File, _)
        db.add_rule(LogicRule::with_metadata(
            "serialization_risk".into(),
            LogicFact::new("serialization_risk", vec![Term::Var(420)]),
            vec![
                LogicFact::new(
                    "cross_lang_call",
                    vec![Term::Var(420), Term::Var(421), Term::atom("SharedFile")],
                ),
                LogicFact::new("taint_source", vec![Term::Var(420), Term::Var(422)]),
            ],
            RuleMetadata::default(),
        ));
    }

    /// Query cross-language vulnerabilities from the database
    pub fn query_interactions(db: &FactDB) -> Vec<CrossLangInteraction> {
        let mut interactions = Vec::new();

        // Rehydrate relational findings back into typed interaction records.
        // Scores are currently heuristic constants and can be model-driven later.
        // Collect FFI risk findings
        for fact in db.get_facts("ffi_risk") {
            if fact.args.len() >= 2 {
                if let (Term::Atom(file), Term::Atom(mechanism)) = (&fact.args[0], &fact.args[1]) {
                    interactions.push(CrossLangInteraction {
                        caller_file: file.clone(),
                        caller_lang: Language::detect(file),
                        callee_file: "foreign".to_string(),
                        callee_lang: Language::Unknown,
                        mechanism: Self::parse_mechanism(mechanism),
                        risk_score: 0.85,
                    });
                }
            }
        }

        // Collect cross-language call facts
        for fact in db.get_facts("cross_lang_call") {
            if fact.args.len() >= 3 {
                if let (Term::Atom(caller), Term::Atom(callee), Term::Atom(mech)) =
                    (&fact.args[0], &fact.args[1], &fact.args[2])
                {
                    interactions.push(CrossLangInteraction {
                        caller_file: caller.clone(),
                        caller_lang: Language::detect(caller),
                        callee_file: callee.clone(),
                        callee_lang: Language::detect(callee),
                        mechanism: Self::parse_mechanism(mech),
                        risk_score: 0.70,
                    });
                }
            }
        }

        interactions
    }

    fn parse_mechanism(s: &str) -> InteractionMechanism {
        match s {
            "CFfi" => InteractionMechanism::CFfi,
            "BeamNif" => InteractionMechanism::BeamNif,
            "BeamPort" => InteractionMechanism::BeamPort,
            "JsFfi" => InteractionMechanism::JsFfi,
            "Subprocess" => InteractionMechanism::Subprocess,
            "SharedFile" => InteractionMechanism::SharedFile,
            "NetworkProtocol" => InteractionMechanism::NetworkProtocol,
            "StdioPipe" => InteractionMechanism::StdioPipe,
            "WasmBoundary" => InteractionMechanism::WasmBoundary,
            _ => InteractionMechanism::Subprocess,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_mechanism_detection() {
        assert_eq!(
            CrossLangAnalyzer::infer_ffi_mechanism(Language::Elixir),
            InteractionMechanism::BeamNif
        );
        assert_eq!(
            CrossLangAnalyzer::infer_ffi_mechanism(Language::ReScript),
            InteractionMechanism::JsFfi
        );
        assert_eq!(
            CrossLangAnalyzer::infer_ffi_mechanism(Language::Zig),
            InteractionMechanism::CFfi
        );
    }

    #[test]
    fn test_family_boundary_detection() {
        let mut db = FactDB::new();
        let file_langs = vec![
            ("src/web.ex".to_string(), Language::Elixir),
            ("ffi/bridge.zig".to_string(), Language::Zig),
            ("src/types.res".to_string(), Language::ReScript),
        ];

        CrossLangAnalyzer::detect_family_boundaries(&mut db, &file_langs);

        // beam, systems, ml — should have 3 boundary facts
        assert!(db.fact_count("language_boundary") >= 3);
    }

    #[test]
    fn test_cross_lang_rule_loading() {
        let mut db = FactDB::new();
        CrossLangAnalyzer::load_rules(&mut db);
        assert_eq!(db.rule_count(), 3);
    }
}
