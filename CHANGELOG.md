# Changelog

## [2.0.0+] - 2026-03-23

### Fixed
- **A2ML parser**: Now handles TOML-like format (key = "value") in addition to S-expression format
- **Manifest lookup**: Tries `0-AI-MANIFEST.a2ml` first before falling back to `AI.a2ml`
- **Language detection**: Skips `external_corpora/`, `third_party/`, and `corpus/` directories to avoid false positives from vendored or reference text

## [2.0.0+] - 2026-03-01

### Added
- **SARIF output format**: `--output-format sarif` for GitHub Security tab integration
- **Assemblyline batch scanning**: Scan entire directories of repos with `assemblyline` subcommand
  - Rayon parallelism: 17.7x speedup (141 repos in 39.9s)
  - BLAKE3 fingerprinting for incremental scanning (infrastructure ready)
  - Sorted output: riskiest repos first
- **Notification pipeline**: `notify` subcommand generates annotated finding summaries
  - Markdown output with severity breakdown per repo
  - `--critical-only` flag for filtering
  - `--create-issues` for GitHub issue creation
- **Cryptographic attestation chain**: Three-phase model (intent, evidence, seal)
  - Pre-execution commitment hashing
  - Rolling evidence accumulator
  - Post-execution binding with optional Ed25519 signing (`--features signing`)
  - A2ML envelope wrapper for attestation bundles
- **i18n support**: ISO 639-1, 10 languages (en, fr, de, es, it, pt, ja, zh, ko, ar)
  - Compile-time safe catalog with `t()` and `t_or_key()` lookups
  - Doc-tested examples
- **Panicbot integration**: JSON output contract verified for gitbot-fleet
  - PA001-PA020 rule mapping for all 20 WeakPointCategory variants
  - Bot directives at `.machine_readable/bot_directives/panicbot.scm`
  - Diagnostics self-check for panicbot readiness
- **Machine-verifiable readiness tests**: 18 tests across CRG grades D/C/B
  - Grade D (Alpha): component runs without crashing
  - Grade C (Beta): correct output on representative input
  - Grade B (RC): edge cases and multi-language support
- **Justfile**: build, test, readiness, readiness-summary, clean, install, dogfood, lint recipes
- **Manifest-first framework detection**: Detects frameworks from Cargo.toml, mix.exs, package.json etc. instead of source scanning (eliminates false positives)

### Fixed
- **Framework detection false positives**: Self-referential matches eliminated by using dependency manifests as primary signal; Rust source scanning removed entirely
- **All compiler warnings**: 0 warnings in both release and test builds
- **Test count**: 269 tests (up from ~30), 0 failures

### Changed
- **Diagnostics**: Now checks panicbot integration readiness (JSON contract, directives)
- **AI.a2ml**: Added panicbot, updated SARIF format, corrected metadata
- **ECOSYSTEM.scm**: Added panicbot with full interface documentation
- **STATE.scm**: Updated with all session 8/9 capabilities and outcomes

## [2.0.0] - 2026-02-08

### Added
- **47-language support**: BEAM (Elixir, Erlang, Gleam), ML (ReScript, OCaml, SML), Lisp (Scheme, Racket), Functional (Haskell, PureScript), Proof (Idris, Lean, Agda), Logic (Prolog, Logtalk, Datalog), Systems (Zig, Ada, Odin, Nim, Pony, D), Config (Nickel, Nix), Scripting (Shell, Julia, Lua), plus 12 nextgen DSLs
- **20 weak point categories**: UnsafeCode, PanicPath, CommandInjection, UnsafeDeserialization, DynamicCodeExecution, UnsafeFFI, AtomExhaustion, InsecureProtocol, ExcessivePermissions, PathTraversal, HardcodedSecret, UncheckedError, InfiniteRecursion, UnsafeTypeCoercion, UncheckedAllocation, UnboundedLoop, BlockingIO, RaceCondition, DeadlockPotential, ResourceLeak
- **miniKanren-inspired logic engine** (`src/kanren/`):
  - Substitution-based unification
  - Forward chaining: derives vulnerability facts from rules
  - Backward queries: find files by vulnerability category
  - Taint analysis: source-to-sink data flow tracking
  - Cross-language vulnerability chain detection (FFI/NIF/Port/subprocess)
  - Search strategy auto-selection (RiskWeighted, BoundaryFirst, LanguageFamily, BreadthFirst, DepthFirst)
- **PanLL event-chain export**: DAW-style timeline export for visualisation
- **Ambush timeline scheduling**: Stressor sequencing with timeline files
- **Report views**: Summary, accordion, dashboard, matrix views + TUI viewer
- **Nickel output format**

### Changed
- **Renamed**: xray -> assail, XRayReport -> AssailReport, src/xray/ -> src/assail/
- **Renamed**: panic-attacker binary -> panic-attack

## [1.0.1] - 2026-02-07

### Fixed
- **CI/CD workflows**: All GitHub Actions now passing
  - Updated MSRV from 1.75.0 to 1.85.0 (required for Cargo.lock v4 format)
  - Fixed invalid codeql-action SHA pins
  - Fixed TruffleHog configuration
  - Fixed EditorConfig indentation violations
- **Code quality**: Resolved clippy warnings, removed unused imports

### Changed
- **MSRV**: Updated from 1.75.0 to 1.85.0

## [1.0.0] - 2026-02-07

### Added
- **Production-ready infrastructure**: RSR compliance, 11 workflows, docs
- **Testing**: 21 unit + 3 integration + 3 regression tests
- **Configuration**: Config file support, EditorConfig, MSRV policy

## [0.2.0] - 2026-02-07

### Fixed
- **Weak points now per-file**: Eliminates duplicates (echidna: 271 -> 15)
- **File locations always populated**: No more `location: None`

### Added
- FileStatistics, Latin-1 fallback, verbose mode, pattern library, integration tests

## [0.1.0] - 2026-02-06

Initial proof-of-concept: Assail static analysis, multi-axis stress testing, logic-based bug signature detection.
