;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Meta-level information for panic-attack (formerly panic-attacker)
;; Media Type: application/meta+scheme

(meta
  (version "1.0")
  (project "panic-attack")

  (architecture-decisions
    (adr
      (id "ADR-001")
      (date "2026-02-06")
      (status "accepted")
      (title "Use Rust for implementation")
      (context "Need memory safety, performance, strong type system")
      (decision "Implement in Rust with Cargo")
      (consequences
        "Memory safety without garbage collection"
        "Excellent CLI tooling with clap"
        "Strong ecosystem for system-level programming"
        "Portable to multiple platforms"))

    (adr
      (id "ADR-002")
      (date "2026-02-06")
      (status "superseded")
      (superseded-by "ADR-008")
      (title "Datalog-inspired signature detection")
      (context "Need expressive bug pattern matching beyond regex")
      (decision "Use Datalog-inspired rules with fact extraction")
      (consequences
        "More powerful than string matching"
        "Extensible rule system"
        "Superseded by miniKanren logic engine in v2.0.0"))

    (adr
      (id "ADR-003")
      (date "2026-02-07")
      (status "accepted")
      (title "Per-file analysis eliminates duplicates")
      (context "v0.1 produced duplicate weak points with running totals")
      (decision "Create fresh ProgramStatistics per file, accumulate into global")
      (consequences
        "Weak point counts accurate (271->15 on echidna)"
        "All locations populated (never null)"
        "FileStatistics provides per-file breakdown"
        "Risk scoring identifies hotspot files"))

    (adr
      (id "ADR-004")
      (date "2026-02-07")
      (status "accepted")
      (title "Latin-1 fallback for non-UTF-8 files")
      (context "Vendored third-party C files with ISO-8859-1 author names")
      (decision "Try UTF-8 first, fallback to encoding_rs WINDOWS_1252, then skip")
      (consequences
        "No crashes on non-UTF-8 files"
        "Verbose mode logs skipped files"
        "Handles common non-UTF-8 cases (Latin-1, ISO-8859-1)"))

    (adr
      (id "ADR-005")
      (date "2026-02-07")
      (status "accepted")
      (title "Infrastructure-first path to v1.0")
      (context "15 weeks for full-feature v1.0 vs. 3-5 days for stable foundation")
      (decision "v1.0 = RSR compliance + tests + CI/CD + polish, defer v0.4-v0.7 features")
      (consequences
        "Faster path to production-ready release"
        "Solid foundation for feature expansion"
        "Feature development continued in v2.0.0"
        "Focus on quality over quantity"))

    (adr
      (id "ADR-006")
      (date "2026-02-07")
      (status "accepted")
      (title "Pattern library wired into attack executor")
      (context "v0.1 defined AttackPattern but never used it")
      (decision "AttackExecutor::with_patterns() applies language/framework-specific patterns")
      (consequences
        "Smarter attack selection"
        "Logs applicable patterns during execution"
        "Framework detection influences strategy"
        "Extensible pattern system for new languages"))

    (adr
      (id "ADR-007")
      (date "2026-02-07")
      (status "accepted")
      (title "RuleSet wired into signature engine")
      (context "v0.1 stored rules but never dispatched on them")
      (decision "detect_from_crash() iterates rules, dispatches by name")
      (consequences
        "Rules are now read and used"
        "Eliminates dead code warnings"
        "Prepares for miniKanren integration"
        "User-definable rules possible in future"))

    (adr
      (id "ADR-008")
      (date "2026-02-08")
      (status "accepted")
      (title "miniKanren-inspired logic engine for relational reasoning")
      (context "Datalog-inspired rules (ADR-002) were too limited for cross-language and taint analysis")
      (decision "Implement miniKanren-inspired engine with substitution-based unification, forward chaining, and backward queries")
      (consequences
        "Taint analysis: source-to-sink data flow tracking across files"
        "Cross-language vulnerability chain detection (FFI/NIF/Port/subprocess boundaries)"
        "Search strategy optimisation (auto-select from 5 strategies)"
        "Forward chaining derives new vulnerability facts from rules"
        "Backward queries find files by vulnerability category"
        "More expressive than Datalog for relational reasoning"))

    (adr
      (id "ADR-009")
      (date "2026-02-08")
      (status "accepted")
      (title "Rename xray to assail throughout codebase")
      (context "xray was a medical metaphor; assail better conveys offensive security testing")
      (decision "Rename all references: xray->assail, XRayReport->AssailReport, src/xray/->src/assail/")
      (consequences
        "Consistent naming across binary, library, and documentation"
        "Binary subcommand: panic-attack assail"
        "Module path: src/assail/"
        "Report type: AssailReport"))

    (adr
      (id "ADR-010")
      (date "2026-02-08")
      (status "accepted")
      (title "47-language support with per-file language detection")
      (context "v0.2 supported 5 languages; hyperpolymath repos use 40+ languages")
      (decision "Expand to 47 languages across 10 families: BEAM, ML, Lisp, Functional, Proof, Logic, Systems, Config, Scripting, NextGen DSLs")
      (consequences
        "Covers all languages in hyperpolymath ecosystem"
        "20 weak point categories (up from ~5)"
        "Per-file language detection with family-specific patterns"
        "Cross-language analysis possible via kanren engine"))

    (adr
      (id "ADR-011")
      (date "2026-03-01")
      (status "accepted")
      (title "Assemblyline batch scanning with rayon parallelism and BLAKE3 fingerprinting")
      (context "Need to scan 100+ repos efficiently; sequential scanning too slow")
      (decision "Use rayon for parallel repo scanning, BLAKE3 for source fingerprinting to enable incremental rescans")
      (consequences
        "17.7x speedup (141 repos in 39.9s vs ~705s sequential)"
        "BLAKE3 fingerprint infrastructure for future delta scanning"
        "Sorted output: riskiest repos first"
        "JSON aggregate report with per-repo breakdowns"))

    (adr
      (id "ADR-012")
      (date "2026-03-01")
      (status "accepted")
      (title "SARIF output format for standardised security reporting")
      (context "GitHub Security tab requires SARIF for code scanning integration")
      (decision "Implement SARIF 2.1.0 output via --output-format sarif")
      (consequences
        "GitHub Security tab integration via codeql-action/upload-sarif"
        "Standard format consumed by multiple security tools"
        "Rules deduplicated by WeakPointCategory"))

    (adr
      (id "ADR-013")
      (date "2026-03-01")
      (status "accepted")
      (title "Cryptographic attestation chain (intent/evidence/seal)")
      (context "Need to prove scans are genuine and untampered for trust chain")
      (decision "Three-phase model: intent (pre-commit), evidence (rolling hash), seal (post-bind)")
      (consequences
        "Scans are cryptographically bound to inputs and outputs"
        "Optional Ed25519 signing via --features signing"
        "A2ML envelope wraps attestation for transport"
        "Diagnostics checks signing health"))

    (adr
      (id "ADR-014")
      (date "2026-03-01")
      (status "accepted")
      (title "i18n support using ISO 639-1 (10-language catalog)")
      (context "Potential for non-English-speaking users; internationalisation should be built in early")
      (decision "Compile-time safe catalog with t() and t_or_key() lookups, 10 languages")
      (consequences
        "All user-facing strings translatable"
        "Doc-tested examples ensure catalog stays valid"
        "ISO 639-1 validation for language codes"))

    (adr
      (id "ADR-015")
      (date "2026-03-01")
      (status "accepted")
      (title "Notification pipeline (markdown-first, critical-only filtering)")
      (context "Assemblyline produces aggregate reports; need human-readable summaries and actionable alerts")
      (decision "notify subcommand generates markdown with severity breakdown, optional critical-only filter, optional GitHub issue creation")
      (consequences
        "Markdown output works in GitHub, email, Slack, etc."
        "--critical-only reduces noise to actionable items only"
        "GitHub issue creation automates remediation workflow"))

    (adr
      (id "ADR-016")
      (date "2026-03-01")
      (status "accepted")
      (title "Manifest-first framework detection (fixes false positives)")
      (context "Source-level substring matching caused self-referential false positives (analyzer detecting its own patterns)")
      (decision "Primary detection from dependency manifests (Cargo.toml, mix.exs, package.json, etc.); Rust excluded from source scanning entirely")
      (consequences
        "Eliminates self-referential false positives"
        "Cargo.toml detection is authoritative for Rust"
        "Source scanning kept for BEAM, Go, Ruby, Python, JS only"
        "~8% overall FP rate (down from higher)"))

    (adr
      (id "ADR-017")
      (date "2026-03-01")
      (status "accepted")
      (title "Machine-verifiable readiness tests (CRG grades D/C/B)")
      (context "Need automated evidence for Component Readiness Grading")
      (decision "tests/readiness.rs with grade-prefixed test names; justfile recipes for summary output")
      (consequences
        "CRG grades derivable from test results"
        "D (Alpha): component runs without crashing"
        "C (Beta): correct output on representative input"
        "B (RC): edge cases and multi-language support"
        "18 tests across 3 grades, automated via just readiness-summary")))

  (development-practices
    (practice
      (name "Zero warnings policy")
      (description "cargo build --release must produce 0 warnings")
      (rationale "Warnings hide real issues, signal poor code quality")
      (enforcement "CI fails on warnings"))

    (practice
      (name "Test-driven quality")
      (description "All features must have tests")
      (rationale "Untested code is untrusted code")
      (target "80% code coverage")
      (current "269 tests: unit, integration, analyzer, readiness (CRG D/C/B), SARIF, PanLL, report, assemblyline, pattern"))

    (practice
      (name "RSR compliance")
      (description "Follow Reproducible Software Repositories standard")
      (rationale "Consistency across hyperpolymath ecosystem")
      (requirements
        "AI manifest (AI.a2ml)"
        "SCM checkpoint files (.machine_readable/)"
        "17 standard workflows"
        "PMPL-1.0-or-later license"))

    (practice
      (name "Semantic versioning")
      (description "MAJOR.MINOR.PATCH with clear upgrade paths")
      (rationale "Predictable releases, clear breaking changes")
      (policy
        "1.x = stable foundation, naming finalised"
        "2.x = major feature expansion (logic engine, 47 langs, batch scanning, attestation)"
        "3.0 = public release (crates.io)"))

    (practice
      (name "Documentation-first")
      (description "Write docs before/during implementation, not after")
      (rationale "Better API design, fewer mistakes")
      (requirements
        "rustdoc for all public APIs"
        "README examples that actually work"
        "CHANGELOG for all releases"))

    (practice
      (name "Eat your own dogfood")
      (description "Run panic-attack on panic-attack itself")
      (rationale "Find bugs, validate thresholds, prove usefulness")
      (status "active: self-scan shows 30 findings, ~8% false positive rate")))

  (design-rationale
    (rationale
      (aspect "Multi-axis testing")
      (reasoning "Real failures are multi-dimensional (CPU + memory + network, not just one)")
      (future "Constraint sets enable simultaneous multi-axis attacks"))

    (rationale
      (aspect "Assail pre-analysis")
      (reasoning "Static analysis guides dynamic testing, avoiding wasted effort")
      (benefit "Recommended attacks based on detected weak points"))

    (rationale
      (aspect "miniKanren logic engine")
      (reasoning "Relational reasoning enables taint analysis, cross-language chains, and search strategy optimisation")
      (inspiration "Mozart/Oz constraint logic programming, miniKanren relational paradigm")
      (components "core.rs (unification, facts, rules), taint.rs (source-sink), crosslang.rs (FFI boundaries), strategy.rs (file prioritisation)"))

    (rationale
      (aspect "Per-file statistics")
      (reasoning "Identify hotspot files, prioritize fixes, avoid duplicates")
      (benefit "Risk scoring highlights worst offenders"))

    (rationale
      (aspect "47-language support")
      (reasoning "One tool for all languages in the hyperpolymath ecosystem")
      (current "47 languages: BEAM, ML, Lisp, Functional, Proof, Logic, Systems, Config, Scripting, NextGen DSLs")
      (benefit "Cross-language vulnerability detection via kanren engine"))

    (rationale
      (aspect "Manifest-first framework detection")
      (reasoning "Source-level substring matching causes self-referential false positives when the analyzer scans its own code")
      (decision "Use dependency manifests (Cargo.toml, mix.exs, etc.) as primary signal; exclude Rust from source scanning")
      (benefit "Eliminates FPs from string literals containing detection patterns"))

    (rationale
      (aspect "Cryptographic attestation")
      (reasoning "Prove scans are genuine and untampered for CI/CD trust chains")
      (components "intent.rs (pre-commit), evidence.rs (rolling hash), seal.rs (post-bind), chain.rs (orchestration), envelope.rs (A2ML wrapper)")
      (benefit "Scans can be verified by echidnabot or other proof verifiers"))

    (rationale
      (aspect "CLI + library")
      (reasoning "Useful standalone and as integration component")
      (benefit "src/lib.rs enables testing, hypatia integration, verisimdb pipeline, panicbot subprocess invocation")))

  (cross-cutting-concerns
    (concern
      (name "Error handling")
      (approach "anyhow for CLI, Result<T, E> for library")
      (policy "Never panic in library code, only in CLI after reporting"))

    (concern
      (name "Performance")
      (approach "Rayon parallelism for batch scanning, search strategy optimisation via kanren")
      (current "Parallel assemblyline scanning (17.7x speedup); single-threaded per-file analysis with risk-weighted prioritisation")
      (future "Incremental analysis via BLAKE3 delta fingerprinting"))

    (concern
      (name "Security")
      (approach "cargo-audit in CI, SBOM generation, self-testing, attestation chain")
      (policy "No unsafe code in panic-attack itself except when required for FFI"))

    (concern
      (name "Portability")
      (approach "Pure Rust, minimal platform-specific code")
      (targets "Linux, macOS, Windows")
      (limitations "Some attacks require Unix tools (timeout command)"))

    (concern
      (name "Extensibility")
      (approach "Pattern library, kanren rule system, pluggable analyzers")
      (current "miniKanren rules for taint, cross-language, and strategy")
      (future "User-definable rules, plugin system, context-fact FP suppression")))

  (metadata
    (created "2026-02-07")
    (updated "2026-03-01")
    (maintainer "Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")))
