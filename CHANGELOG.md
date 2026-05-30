# Changelog

## [Unreleased]

### Added (2026-05-30) — issue #33 closure
- **VeriSimDB hexad persistence complete (issue #33 S1–S3)** — per-finding
  hexads, campaign state lifecycle, and S-expression query DSL all shipped:
  - **S1**: per-finding hexad emission gated by
    `PANIC_ATTACK_STORE_FINDING_HEXADS=1` (`src/storage/mod.rs ::
    build_finding_hexads`, subject format
    `finding:<repo>:<file>:<line>:<category>`).
  - **S2**: `panic-attack campaign` subcommand (`register-pr`, `dismiss`,
    `status`, `poll`) drives finding lifecycle with state transitions
    persisted as campaign hexads. `poll` performs GitHub PR state
    transitions (open → pr-filed → pr-merged / pr-closed).
  - **S3**: `panic-attack query <expr>` evaluates a small S-expression
    language over the persisted hexads. Heads: `category`, `rule-id`,
    `severity`, `repo`, `file`, `pr-state`, `since`, `crosslang`, `diff`,
    `and`, `or`, `not`.
- **Query parser: `(diff :since :category ...)` head + inline `:keyword
  VALUE` kwargs on every unary head** (`src/query/mod.rs`). The issue
  body's three literal example expressions now parse verbatim:
  - `(crosslang :from FFI :to ProofDrift)` — already worked.
  - `(category PA001 :severity Critical :pr-state nil)` — now parses as
    `(and (rule-id PA001) (severity Critical) (pr-state nil))`, with
    PA-prefixed values on `category` auto-routed to `rule-id` so the
    query actually matches findings.
  - `(diff :since 2026-04-12 :category PA022)` — new `diff` head is
    keyword-only sugar for an `(and ...)` over its kwarg pairs.
  Inline kwargs are accepted on `category`, `rule-id`, `severity`, `repo`,
  `file`, `pr-state`, and `since` — adding a `:keyword VALUE` after the
  positional value desugars to `(and (head positional) (kw value) ...)`.
  Behaviour unchanged for existing query expressions; 12 new unit tests.

### Added (2026-04-18)
- **User-classification registry** (`assail::UserClassification`,
  `load_user_classifications`, `apply_user_classifications`): panic-attack
  now reads an optional project-local classification file at every assail
  pass and flips matching findings to `suppressed = true` after the kanren
  structural-suppression pass. Two lookup paths:
  - `<project_root>/audits/assail-classifications.a2ml` (preferred)
  - `<project_root>/.panic-attack-classifications.a2ml` (fallback)
  File format is a simple A2ML S-expression with `(classification (file …)
  (category …) (audit …) (rationale …))` blocks; `;;` line comments
  ignored. The registry pattern lets repositories record audited findings
  out-of-band from the source under scan so a PR adding a new unsafe
  block cannot self-suppress without a reviewable companion edit to
  the registry.
- **Rocq scaffold classifier** (`analyze_coq` +
  `count_rocq_unverified_postulates` + `is_rocq_abstraction_parameter`):
  the Rocq detector no longer counts Section-scoped `Variable` /
  `Hypothesis` / `Parameter` declarations (they discharge at `End
  Section`) and classifies module-level `Parameter` declarations by
  stated type: carrier types (`Type`, `Set`), decidability witnesses
  (`forall _, { _ = _ } + { _ <> _ }`), and function types with a
  concrete non-Prop codomain are treated as abstraction parameters.
  Prop-valued declarations (classical excluded-middle, choice,
  unresolved theorem statements) remain counted. Removes the
  false-positive stream that surfaced on every canonical-proof-suite
  scaffold.

### Changed
- **Suppression pipeline**: `analyze()` and `analyze_verbose()` now
  chain `apply_suppression` → `apply_user_classifications` in that
  order; the explicit post-analyze calls in `assail::analyze` and
  `assail::analyze_verbose` at the module boundary are retained for
  API-contract clarity but are no-ops when an `Analyzer` pass has
  already run.
- **Rocq test coverage**: 12 new unit tests across `analyzer.rs`
  (Section-scoped Variables / module-level Type carriers / decidable
  equality / concrete-codomain functions / Prop-valued axioms /
  missing type annotation / full scaffold shape — 7 tests) and
  `mod.rs` (missing-registry / single-entry / multiple-entry /
  comment handling / end-to-end suppression-flip — 5 tests).

### Verified
- 007 canonical-proof-suite scan: active finding count **8 → 0**
  (the 6 scaffold ProofDrifts via the detector enhancement, the 2
  `zig_bridge.rs` UnsafeCode findings via the classification registry
  pointing at `audits/audit-ffi-unsafe.md §1`). No in-source
  suppression markers added to either repo.

## [2.5.0] - 2026-04-12

### Added
- **InputBoundary category (PA024)**: New weak point category detecting unguarded structured-data
  parsing at trust boundaries.
  - **Rust**: `serde_cbor::from_slice`/`from_reader`, `ciborium::de::from_reader`,
    `rmp_serde::from_slice`/`from_read` — CBOR/MessagePack deserialization without a
    validation layer (Medium). All five crate patterns flagged.
  - **JavaScript/ReScript**: `JSON.parse(` in files without any `try`/`catch` context (High).
    Files that do wrap their JSON.parse in try/catch are not flagged.
  - **Julia**: `JSON3.read(` and `JSON.parse(` without error handling context (High).
  - Taint tracking from external reads to trust-sensitive sinks deferred to kanren phase.
  - A2ML boundary detection deferred — requires cross-file analysis.
- **PA024 → panicbot**: InputBoundary mapped to `static-analysis/input-boundary`, 0.72
  confidence, Control tier, Partial fixability.
- **MutationGap category (PA025)**: New weak point category detecting mutation and chaos
  coverage gaps in test suites.
  - **Rust** (project-level): Tests present (`mod tests` / `#[cfg(test)]`) but no
    `cargo-mutants` config in `Cargo.toml` or `mutants.toml` — mutation tooling absent (Low).
  - **Julia** (per-file): `@testset` blocks where every `@test` is a type-check assertion
    (`@test … isa …`) with no value assertions — no assertion diversity (Medium).
  - **Elixir** (per-file): Test files using `ExUnit.Case` without importing `ExUnitProperties`
    or `StreamData` for property-based testing (Low).
  - Coverage-plus-mutation-score check deferred — requires runtime coverage data.
- **PA025 → panicbot**: MutationGap mapped to `static-analysis/mutation-gap`, 0.80
  confidence, Substitute tier, Partial fixability.
- **Idris2 ABI completeness**: `PatternCompleteness.idr` updated — InputBoundary (Rust/JS/Julia)
  and MutationGap (Rust/Julia/Elixir) added to `WPCategory` with `detectorsFor` entries.

### Changed
- **Category count**: 23 → 25 (added InputBoundary, MutationGap)
- **v2.5.0 milestone**: All tractable items complete. Two deferred items each for
  `input_boundary` (taint+A2ML) and `mutation` (coverage-score), and three for
  `crypto_misuse` (key-reuse, nonce-reuse, sig-verify) marked as statically undetectable
  or requiring runtime data.

## [2.3.0] - 2026-04-12

### Added
- **CryptoMisuse category (PA022)**: New weak point category detecting cryptographic primitive
  misuse across five languages. Context-window heuristic (±200 chars) restricts MD5/SHA-1
  findings to security-sensitive usage — MD5 for file checksums is not flagged.
  - **Rust**: `md5::compute`/`Md5::new` and `sha1::Sha1`/`Sha1::new` in security context (High);
    `==` comparison on `secret`/`password`/`token`/`key` variables (Critical — timing attack).
  - **Python**: `hashlib.md5()`/`hashlib.sha1()` in security context (High);
    `==` on secret-named variables — use `hmac.compare_digest()` instead (Critical).
  - **JavaScript**: `crypto.createHash('md5')` and `crypto.createHash('sha1')` (High);
    `crypto.createHash('sha256')` is fine and not flagged.
  - **Go**: `md5.New()`/`md5.Sum()` and `sha1.New()`/`sha1.Sum()` in security context (High).
  - **Elixir**: `:crypto.hash(:md5, ...)` and `:crypto.hash(:sha, ...)` (High);
    `:crypto.mac(:hmac, :sha, ...)` is acceptable (HMAC-SHA1 is not broken) and not flagged.
  - Key-reuse and nonce-reuse deferred — not reliably detectable statically.
- **has_security_context() helper**: Module-level helper function checks ±200 char window
  around a pattern match for security vocabulary (password, secret, token, auth, key,
  credential, hash, sign, verify, encrypt) to reduce false positives on benign MD5/SHA-1 use.
- **PA022 → panicbot**: CryptoMisuse mapped to fleet category `static-analysis/crypto-misuse`
  with 0.75 confidence, Eliminate tier, Partial fixability. Confidence is honest — the context
  window has a modest false-positive rate when security vocabulary appears for unrelated reasons.
- **Idris2 ABI completeness**: `PatternCompleteness.idr` updated — CryptoMisuse added to
  `WPCategory` with `detectorsFor` covering Rust, Python, JavaScript, Go, Elixir.

## [2.2.0] - 2026-04-12

### Added
- **SupplyChain category (PA023)**: New weak point category detecting dependency and build
  integrity gaps: `Cargo.toml` git dependencies without `rev =`, absent `Cargo.lock` for
  library/binary crates, Julia `Manifest.toml` without `git-tree-sha1` hash entries,
  `flake.nix` inputs without `narHash`, and `deno.json` import map entries without a version
  pin. Project-level manifest checks run as a synthesis stage after file analysis.
  Confidence 0.85 — these are explicit manifest/config patterns with low false-positive rate.
- **PA023 → panicbot**: SupplyChain mapped to fleet category `static-analysis/supply-chain`
  with 0.85 confidence, Eliminate tier, fixable (adding pins resolves the finding).
- **Idris2 ABI completeness**: `PatternCompleteness.idr` updated — SupplyChain added to
  `WPCategory` with `detectorsFor` covering Rust, Julia, Nix, JavaScript.

### Changed
- **Category count**: 22 → 23 (added SupplyChain)

## [2.1.0] - 2026-04-12

### Added
- **ProofDrift category (PA021)**: New weak point category detecting formal verification drift
  across all proof assistant languages. Catches banned proof escape hatches (`sorry`, `Admitted`,
  `believe_me`, `oops`, `trustMe`, `assert_total`, `%partial`, `{-# TERMINATING #-}`) and
  Julia mirror files substituting `@test x isa Y` or `# sorry` comments for formal proofs.
  Confidence 0.92 — proof escape hatches have essentially no false positives in their file types.
- **Isabelle/HOL language support**: `.thy` files parsed with `analyze_isabelle()` detecting
  `sorry`, `oops`, and `axiomatization` as ProofDrift findings.
- **Coq/Rocq language support**: `.v` files parsed with `analyze_coq()` detecting `Admitted`,
  `admit` tactic, `Axiom`/`Parameter` declarations, and `Obj.magic` in extraction artifacts.
- **Isabelle + Coq dispatch**: Both new languages wired into `analyze_inner()` dispatch.
- **Lean4 ProofDrift upgrade**: `sorry` upgraded from UnsafeCode → ProofDrift (Critical).
  Added `unsafeNativeIO`/`unsafeBaseIO` as ProofDrift (IO discipline bypass).
- **Agda ProofDrift upgrade**: `trustMe`/`primTrustMe` upgraded to ProofDrift (Critical).
  Added `{-# TERMINATING #-}`, `{-# NON_TERMINATING #-}`, bare `postulate` as ProofDrift.
- **Idris2 ProofDrift upgrade**: `believe_me` already ProofDrift; added `assert_total` (High)
  and `%partial` (Medium) as ProofDrift findings.
- **Julia mirror detection**: `# sorry`, `# TODO: prove`, `# admitted` comments and
  `@test x isa Y` patterns (no value check) flagged as ProofDrift in Julia files.
- **FP suppression wiring**: `apply_suppression()` now runs on every scan, marking
  weak points `suppressed: true` when logic engine finds defensive-pattern context.
  Suppressed items stay in report for audit transparency; filtered by panicbot and CI gates.
- **PA021 → panicbot**: ProofDrift mapped to fleet category `static-analysis/proof-drift`
  with 0.92 confidence and Control tier.
- **Idris2 ABI completeness**: `PatternCompleteness.idr` updated — Isabelle, Coq added to
  `Lang` enum; ProofDrift added to `WPCategory` with `detectorsFor` covering all new languages.
- **Hypatia integration**: JSON AssailReport consumed by Hypatia Elixir rules. Logtalk
  export removed 2026-04-12.

### Changed
- **Language count**: 47 → 49 (added Isabelle, Coq)
- **Category count**: 20 → 21 (added ProofDrift)
- **Verbose output**: Two views — filtered (active, what CI sees) and unfiltered (total,
  audit transparency) with explicit labelling of what each count means.

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
