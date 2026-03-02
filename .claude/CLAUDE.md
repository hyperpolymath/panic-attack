# Panic Attack - Project Instructions

## Overview

Static analysis and bug signature detection tool. Scans source code for weak points (unwrap/expect, unsafe blocks, panic sites, error handling gaps, command injection, unsafe deserialization, FFI boundaries, atom exhaustion, and more) across 47 programming languages.

**Position in AmbientOps ecosystem**: Part of the hospital model, loosely affiliated. Sits alongside the Operating Room as a diagnostic tool for software health (while hardware-crash-team handles hardware health). Independent top-level repo, but feeds findings to the hospital's Records system via verisimdb.

**Relationship to AmbientOps**: See [ambientops/.claude/CLAUDE.md](https://github.com/hyperpolymath/ambientops/blob/main/.claude/CLAUDE.md) for the hospital model overview.

**IMPORTANT: This tool was renamed on 2026-02-08:**
- Binary: `panic-attacker` → `panic-attack`
- Subcommand: `xray` → `assail`
- Module: `src/xray/` → `src/assail/`
- Type: `XRayReport` → `AssailReport`
- Report header: `X-RAY` → `ASSAIL`

## Architecture

```
src/
├── main.rs              # CLI entry point (clap) — 20 subcommands
├── lib.rs               # Library API
├── types.rs             # Core types (AssailReport, WeakPoint, etc.)
├── assail/              # Static analysis engine
│   ├── mod.rs           # Public API: analyze(), analyze_verbose()
│   ├── analyzer.rs      # 47-language analyzer with per-file detection
│   └── patterns.rs      # Language-specific attack patterns
├── kanren/              # miniKanren-inspired logic engine (v2.0.0)
│   ├── mod.rs           # Module entry, re-exports
│   ├── core.rs          # Term, Substitution, unification, FactDB, forward chaining
│   ├── taint.rs         # TaintAnalyzer: source→sink tracking
│   ├── crosslang.rs     # CrossLangAnalyzer: FFI boundary detection
│   └── strategy.rs      # SearchStrategy: risk-weighted file prioritisation
├── attack/              # 6-axis stress testing
│   ├── executor.rs      # Attack execution engine
│   └── strategies.rs    # Per-axis attack strategies
├── signatures/          # Logic-based bug signature detection
│   ├── engine.rs        # SignatureEngine (use-after-free, deadlock, etc.)
│   └── rules.rs         # Detection rules
├── report/              # Report generation and output
│   ├── mod.rs           # Report generation API
│   ├── generator.rs     # AssaultReport builder
│   └── formatter.rs     # Output formatting (text + JSON)
├── assemblyline.rs      # Batch scanning with rayon parallelism + BLAKE3
├── notify.rs            # Designer notification pipeline (markdown + GitHub issues)
├── attestation/         # Cryptographic attestation chain
│   ├── mod.rs           # Three-phase chain: intent → evidence → seal
│   ├── intent.rs        # Pre-execution commitment
│   ├── evidence.rs      # Rolling hash accumulator
│   ├── seal.rs          # Post-execution binding
│   ├── chain.rs         # Chain builder orchestration
│   └── envelope.rs      # A2ML envelope wrapper
├── ambush/              # Ambient stressors + DAW-style timeline
├── amuck/               # Mutation combinations
├── abduct/              # Isolation + time-skew
├── adjudicate/          # Campaign verdict aggregation
├── axial/               # Reaction observation
├── a2ml/                # AI manifest protocol
├── panll/               # PanLL event-chain export
├── storage/             # Filesystem + VerisimDB persistence
├── i18n/                # Multi-language support (ISO 639-1, 10 languages)
└── diagnostics.rs       # Self-check for Hypatia/gitbot-fleet
```

## Build & Test

```bash
cargo build --release
cargo test

# Run scan:
panic-attack assail /path/to/repo
panic-attack assail /path/to/repo --output report.json
panic-attack assail /path/to/repo --verbose

# Install:
cp target/release/panic-attack ~/.asdf/installs/rust/nightly/bin/
```

## Key Design Decisions

- **47 language analyzers**: Rust, C/C++, Go, Python, JavaScript, Ruby, Elixir, Erlang, Gleam, ReScript, OCaml, SML, Scheme, Racket, Haskell, PureScript, Idris, Lean, Agda, Prolog, Logtalk, Datalog, Zig, Ada, Odin, Nim, Pony, D, Nickel, Nix, Shell, Julia, Lua, + 12 nextgen DSLs
- **20 weak point categories**: UnsafeCode, PanicPath, CommandInjection, UnsafeDeserialization, AtomExhaustion, UnsafeFFI, PathTraversal, HardcodedSecret, etc.
- **Per-file language detection**: Each file analyzed with its own language-specific patterns
- **miniKanren logic engine**: Relational reasoning for taint analysis, cross-language vulnerability chains, and search strategy optimisation
- **Latin-1 fallback**: Non-UTF-8 files handled gracefully
- **JSON output**: Machine-readable for pipeline integration

## miniKanren Logic Engine (v2.0.0)

The kanren module provides:
- **Taint analysis**: Tracks data flow from sources (user input, network, deserialization) to sinks (eval, shell commands, SQL queries)
- **Cross-language reasoning**: Detects vulnerability chains across FFI/NIF/Port/subprocess boundaries
- **Search strategies**: Auto-selects RiskWeighted, BoundaryFirst, LanguageFamily, BreadthFirst, or DepthFirst based on project characteristics
- **Forward chaining**: Derives new vulnerability facts from rules applied to existing facts
- **Backward queries**: Given a vulnerability type, finds which files could cause it

## Deployment Modes

Three self-contained modes — none requires the others:

1. **Standalone** (USB/laptop/air-gapped): Single binary, zero deps, `assail`/`assault` individual targets
2. **Panicbot** (gitbot-fleet/CI): Automated JSON scanning, PA001–PA020 codes, bot directives
3. **Mass-panic** (assemblyline + verisimdb + Chapel): Org-scale batch scanning with incremental BLAKE3, hexad persistence, delta reporting, notifications. Chapel (planned) for distributed multi-machine orchestration.

## Planned Features (Next Priorities)

1. **verisimdb HTTP API integration**: Push hexads via REST (awaiting API stabilisation)
2. **kanren context-facts**: ~10 rules for FP suppression (~8% -> ~2-3%)
3. **hypatia pipeline**: Export kanren facts as Logtalk predicates via PanLL
4. **Shell completions**: bash, zsh, fish, nushell
5. **Chapel metalayer**: Distributed `coforall` scanning across compute clusters

## Integration Points

- **panicbot**: gitbot-fleet verifier bot — invokes `panic-attack assail --output-format json`, translates WeakPoints to Findings (PA001-PA020). Directives at `.machine_readable/bot_directives/panicbot.scm`
- **verisimdb**: Store scan results as hexads (document + semantic modalities). File I/O works, API planned
- **hypatia**: Neurosymbolic rule engine processes findings. Env var watcher in diagnostics
- **panll**: Event-chain export for three-pane visualisation. Working via `panll` subcommand
- **assemblyline**: Batch scanning of repo directories. Rayon parallelism, BLAKE3 fingerprinting
- **notify**: Notification pipeline. Assemblyline -> markdown summaries -> GitHub issues
- **attestation**: Cryptographic chain (intent/evidence/seal). Optional Ed25519 signing
- **echidnabot**: Proof verification of scan claims (planned)
- **hardware-crash-team**: Sibling tool (hardware diagnostics vs software analysis)

## Readiness Tests (CRG)

Machine-verifiable Component Readiness Grade tests in `tests/readiness.rs`:
- **Grade D (Alpha)**: Component runs without crashing on valid input
- **Grade C (Beta)**: Component produces correct output on representative input
- **Grade B (RC)**: Component handles edge cases and multiple input types

Run with `just readiness` or `just readiness-summary`.

## Code Style

- SPDX headers on all files: `PMPL-1.0-or-later`
- Author: Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
- Use anyhow::Result for error handling
- Serde derive on public types for JSON serialization
- Zero compiler warnings policy (release + test builds)
