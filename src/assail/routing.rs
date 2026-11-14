// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Which analyzer each language is sent to, and when cross-language checks
//! run (PA1).
//!
//! `analyze_inner` dispatches on [`route`] instead of matching on the
//! language directly, so the table here is the dispatch, not a copy of it.
//! Both `match`es below are exhaustive with no wildcard: a new `Language`
//! fails to compile until it is given a route, and a new `Route` fails to
//! compile until it is given an analyzer.
//!
//! The claims about the table are tested exhaustively in this module's
//! tests (`TESTED` in `PROOF-NEEDS.adoc`; the Creusot/Pearlite and Verus
//! proofs remain open).

use crate::types::Language;

/// The analyzer a file of a given language is handed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Route {
    /// No source language: a registered configuration or build-input
    /// adapter handles the file, if one matches.
    InputAdapter,
    Php,
    Rust,
    CCpp,
    Go,
    Python,
    JavaScript,
    Ruby,
    Elixir,
    Erlang,
    Gleam,
    ReScript,
    OCaml,
    StandardML,
    Lisp,
    Haskell,
    PureScript,
    Idris,
    Lean,
    Agda,
    Isabelle,
    Coq,
    Logic,
    Zig,
    Ada,
    Odin,
    Nim,
    Pony,
    DLang,
    Config,
    Shell,
    Julia,
    Lua,
    NextgenDsl,
    Java,
    /// The language-neutral fallback, for languages with no dedicated
    /// analyzer.
    Generic,
}

/// The analyzer for `lang`.
pub(crate) fn route(lang: Language) -> Route {
    use Language as L;
    match lang {
        L::Unknown => Route::InputAdapter,
        L::Php => Route::Php,
        L::Rust => Route::Rust,
        L::C | L::Cpp => Route::CCpp,
        L::Go => Route::Go,
        L::Python => Route::Python,
        L::JavaScript => Route::JavaScript,
        L::Ruby => Route::Ruby,
        L::Elixir => Route::Elixir,
        L::Erlang => Route::Erlang,
        L::Gleam => Route::Gleam,
        L::ReScript => Route::ReScript,
        L::OCaml => Route::OCaml,
        L::StandardML => Route::StandardML,
        L::Scheme | L::Racket => Route::Lisp,
        L::Haskell => Route::Haskell,
        L::PureScript => Route::PureScript,
        L::Idris => Route::Idris,
        L::Lean => Route::Lean,
        L::Agda => Route::Agda,
        L::Isabelle => Route::Isabelle,
        L::Coq => Route::Coq,
        L::Prolog | L::Logtalk | L::Datalog => Route::Logic,
        L::Zig => Route::Zig,
        L::Ada => Route::Ada,
        L::Odin => Route::Odin,
        L::Nim => Route::Nim,
        L::Pony => Route::Pony,
        L::DLang => Route::DLang,
        L::Nickel | L::Nix => Route::Config,
        L::Shell => Route::Shell,
        L::Julia => Route::Julia,
        L::Lua => Route::Lua,
        L::WokeLang
        | L::Eclexia
        | L::MyLang
        | L::JuliaTheViper
        | L::Oblibeny
        | L::Anvomidav
        | L::AffineScript
        | L::Ephapax
        | L::BetLang
        | L::ErrorLang
        | L::VCL
        | L::FBQL => Route::NextgenDsl,
        L::Java => Route::Java,
        L::Chapel => Route::Generic,
    }
}

impl Route {
    /// The function that `analyze_inner` calls for this route.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn analyzer(self) -> &'static str {
        match self {
            Route::InputAdapter => "input_adapters::Adapter::analyze",
            Route::Php => "php::analyze",
            Route::Rust => "analyze_rust",
            Route::CCpp => "analyze_c_cpp",
            Route::Go => "analyze_go",
            Route::Python => "analyze_python",
            Route::JavaScript => "analyze_javascript",
            Route::Ruby => "analyze_ruby",
            Route::Elixir => "analyze_elixir",
            Route::Erlang => "analyze_erlang",
            Route::Gleam => "analyze_gleam",
            Route::ReScript => "analyze_rescript",
            Route::OCaml => "analyze_ocaml",
            Route::StandardML => "analyze_sml",
            Route::Lisp => "analyze_lisp",
            Route::Haskell => "analyze_haskell",
            Route::PureScript => "analyze_purescript",
            Route::Idris => "analyze_idris",
            Route::Lean => "analyze_lean",
            Route::Agda => "analyze_agda",
            Route::Isabelle => "analyze_isabelle",
            Route::Coq => "analyze_coq",
            Route::Logic => "analyze_logic",
            Route::Zig => "analyze_zig",
            Route::Ada => "analyze_ada",
            Route::Odin => "analyze_odin",
            Route::Nim => "analyze_nim",
            Route::Pony => "analyze_pony",
            Route::DLang => "analyze_dlang",
            Route::Config => "analyze_config",
            Route::Shell => "analyze_shell",
            Route::Julia => "analyze_julia",
            Route::Lua => "analyze_lua",
            Route::NextgenDsl => "analyze_nextgen_dsl",
            Route::Java => "analyze_java",
            Route::Generic => "analyze_generic",
        }
    }
}

/// Whether the cross-language checks run over a file's own content.
///
/// They run on every source file and on no structured configuration file:
/// configuration is analysed as parsed keys and values, and treating its
/// comments or schema identifiers as executable source creates false
/// findings. Scripts embedded in configuration are still checked, each on
/// its own, by the input-adapter route.
pub(crate) fn runs_cross_language(is_configuration: bool) -> bool {
    !is_configuration
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assail::analyzer::Analyzer;
    use crate::types::WeakPointCategory;
    use std::collections::BTreeSet;
    use std::fs;
    use tempfile::TempDir;

    /// Language-analyzer methods defined in analyzer.rs: every
    /// `fn analyze_<name>(&self, content: &str, ...)`. Read from the source,
    /// so a new analyzer is seen without anyone listing it here.
    fn analyzer_methods_in_source() -> BTreeSet<String> {
        let source = include_str!("analyzer.rs");
        let compact: String = source.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut found = BTreeSet::new();
        for piece in compact.split("fn analyze_").skip(1) {
            let name: String = piece
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let rest = &piece[name.len()..];
            if rest.starts_with("( &self, content: &str,")
                || rest.starts_with("(&self, content: &str,")
            {
                found.insert(format!("analyze_{name}"));
            }
        }
        found
    }

    /// Methods with the analyzer signature that no language routes to by
    /// design: helpers run on every file or called from other analyzers.
    const NOT_LANGUAGE_ANALYZERS: [&str; 1] = ["analyze_cross_language"];

    fn snake(lang: Language) -> String {
        let name = format!("{lang:?}");
        let mut out = String::new();
        for (i, c) in name.chars().enumerate() {
            if c.is_ascii_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        }
        out
    }

    /// Claim 1a: every language analyzer in the source is reached by some
    /// language. An analyzer nothing routes to is dead code.
    #[test]
    fn every_language_analyzer_is_reached() {
        let routed: BTreeSet<&str> = Language::ALL.iter().map(|l| route(*l).analyzer()).collect();
        let methods = analyzer_methods_in_source();
        assert!(
            methods.len() > 30,
            "source scan found only {methods:?}: the signature pattern no longer matches"
        );
        for method in &methods {
            if NOT_LANGUAGE_ANALYZERS.contains(&method.as_str()) {
                continue;
            }
            assert!(
                routed.contains(method.as_str()),
                "{method} exists in analyzer.rs but no language routes to it"
            );
        }
    }

    /// Claim 1b: every routed analyzer exists, and no language goes to the
    /// generic fallback while a dedicated analyzer for it exists.
    #[test]
    fn no_language_falls_back_while_a_dedicated_analyzer_exists() {
        let methods = analyzer_methods_in_source();
        for lang in Language::ALL {
            let r = route(lang);
            let name = r.analyzer();
            if name.starts_with("analyze_") {
                assert!(
                    methods.contains(name),
                    "{lang:?} routes to {name}, which analyzer.rs does not define"
                );
            }
            if r == Route::Generic {
                let own = format!("analyze_{}", snake(lang));
                assert!(
                    !methods.contains(&own),
                    "{lang:?} falls back to analyze_generic, but {own} exists"
                );
            }
        }
    }

    /// Claim 2: cross-language checks run exactly on non-configuration
    /// content, and on scripts embedded in configuration.
    #[test]
    fn cross_language_checks_run_exactly_off_configuration() {
        assert!(runs_cross_language(false));
        assert!(!runs_cross_language(true));

        // Built at run time so this source file holds no insecure URL of its
        // own for panic-attack's self-scan to report.
        let url = |path: &str| format!("{}://example.org/{path}", "http");
        let tmp = TempDir::new().unwrap();
        // A Justfile is configuration. Its variable is configuration content;
        // its recipe body is an embedded shell script. The recipe URL is
        // quoted: the cross-language detector strips `//` comments first,
        // which also cuts an unquoted URL (a separate recall gap).
        fs::write(
            tmp.path().join("Justfile"),
            format!(
                "mirror := \"{}\"\n\nfetch:\n    curl \"{}\"\n",
                url("variable"),
                url("recipe")
            ),
        )
        .unwrap();
        fs::write(
            tmp.path().join("main.lua"),
            format!("local url = \"{}\"\nprint(url)\n", url("source")),
        )
        .unwrap();

        let report = Analyzer::new(tmp.path()).unwrap().analyze().unwrap();
        let insecure: Vec<_> = report
            .weak_points
            .iter()
            .filter(|w| w.category == WeakPointCategory::InsecureProtocol)
            .collect();

        assert!(
            insecure.iter().any(|w| w.description.contains("main.lua")),
            "source file was not checked: {insecure:?}"
        );
        let justfile: Vec<_> = insecure
            .iter()
            .filter(|w| w.description.contains("Justfile"))
            .collect();
        assert!(
            justfile.iter().any(|w| w.description.contains("embedded")),
            "the recipe's embedded script was not checked: {insecure:?}"
        );
        assert!(
            justfile.iter().all(|w| w.description.contains("embedded")),
            "configuration content was checked as source: {insecure:?}"
        );
    }

    /// Claim 3: the language counts the README states are the count the
    /// table supports (every language except the `Unknown` sentinel).
    #[test]
    fn readme_language_counts_match_the_table() {
        let supported = Language::ALL
            .iter()
            .filter(|l| **l != Language::Unknown)
            .count();
        let readme = include_str!("../../README.adoc");
        let claims = [
            ("badge", "languages-", "-blue"),
            ("capabilities", "**", "-language static analysis"),
            ("summary", "* ", " supported languages"),
        ];
        for (label, before, after) in claims {
            let stated = readme
                .lines()
                .find_map(|line| {
                    let end = line.find(after)?;
                    let start = line[..end].rfind(before)? + before.len();
                    line[start..end].parse::<usize>().ok()
                })
                .unwrap_or_else(|| panic!("README no longer states the {label} count"));
            assert_eq!(
                stated, supported,
                "README {label} says {stated} languages; the routing table supports {supported}"
            );
        }
    }
}
