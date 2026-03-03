# SPDX-License-Identifier: PMPL-1.0-or-later

# panic-attack Roadmap

## Current State: v2.0.0

**19,000+ lines of Rust. 269 tests. 0 warnings. 20 subcommands. 47 languages.**

| Component | Status | Notes |
|---|---|---|
| Assail static analysis | Stable | 47 language-specific analyzers, 20 weak point categories |
| Attack executor (6 axes) | Stable | CPU, memory, disk, network, concurrency, time |
| miniKanren logic engine | Stable | Taint analysis, cross-language reasoning, search strategies |
| Signature detection | Stable | miniKanren-inspired bug detection (use-after-free, deadlock, etc.) |
| Report generation | Stable | JSON, YAML, Nickel, SARIF output + TUI/GUI viewers |
| Assemblyline batch scanning | Stable | Rayon parallelism (17.7x speedup), BLAKE3 fingerprinting |
| Notification pipeline | Stable | Markdown summaries, critical-only filtering, GitHub issues |
| Cryptographic attestation | Stable | Three-phase chain: intent, evidence, seal |
| i18n (10 languages) | Stable | ISO 639-1, compile-time-safe catalog |
| Panicbot integration | Stable | JSON contract verified (PA001-PA020), bot directives |
| A2ML export/import | Stable | Schema-versioned, attestation envelope support |
| PanLL event-chain export | Stable | DAW-style timeline export for visualisation |
| CLI (20 subcommands) | Stable | assail, attack, assault, ambush, amuck, abduct, etc. |
| Tests | 269 tests | Unit, integration, analyzer, readiness (CRG D/C/B) |

### Tested Against

- **panic-attack itself** (19,113 lines Rust): 30 findings, ~8% FP rate
- **gitbot-fleet** (Rust): 76 findings across all bots
- **hypatia** (Elixir): 51 findings, OTP framework detected
- **141 hyperpolymath repos**: 3,561 weak points via assemblyline (39.9s with rayon)

---

## Completed Milestones

### v2.0.0 — 47-Language Logic Engine (2026-02-08)

- 47 programming languages across 10 families
- 20 weak point categories
- miniKanren-inspired logic engine (taint analysis, cross-language, search strategies)
- Renamed xray -> assail, panic-attacker -> panic-attack

### v2.1.0 — Mass-Panic Mode (2026-03-02)

- Incremental assemblyline with BLAKE3 fingerprint cache (`--incremental`, `--cache`)
- VerisimDB hexad persistence for assemblyline aggregate reports
- `--store` wired into assemblyline handler (was only assail/assault before)
- Three deployment modes documented: standalone, panicbot, mass-panic
- PanLL "Mass Panic" panel: GUI for assemblyline batch scanning with repo discovery, select-all/checkbox controls, incremental BLAKE3, progress tracking, delta comparison, sort/filter, notification generation
- Fixed pre-existing migration_metrics test failures (269 tests, 0 failures)

### v2.0.0+ — Session 8/9 Features (2026-03-01)

- SARIF output format (GitHub Security tab integration)
- Assemblyline batch scanning (rayon parallelism, BLAKE3 fingerprinting)
- Notification pipeline (markdown + critical-only + GitHub issues)
- Cryptographic attestation chain (intent -> evidence -> seal)
- i18n support (ISO 639-1, 10 languages)
- Manifest-first framework detection (fixed false positives)
- Machine-verifiable readiness tests (CRG grades D/C/B)
- Panicbot integration (JSON contract, diagnostics, bot directives)
- Zero compiler warnings across release + test builds

### v1.0.0 — Production Release (2026-02-07)

- RSR compliance, CI/CD, comprehensive documentation
- 11 GitHub Actions workflows

### v0.2.0 — Quality Fixes (2026-02-07)

- Per-file analysis, locations, Latin-1 fallback, zero warnings

### v0.1.0 — Proof of Concept (2026-02-06)

- Initial assail + 6-axis attacks + signature detection

---

## v2.1.0 — Bulk Scanning & Persistence (NEXT)

**Theme: Production pipeline for organisation-scale scanning (mass-panic mode)**

- [x] Incremental assemblyline: skip unchanged repos via BLAKE3 delta (`--incremental`)
- [x] Assemblyline checkpointing: resume interrupted sweeps via fingerprint cache
- [x] Delta reporting: `panic-attack diff` compares any two reports side-by-side
- [x] `--store` flag for automatic verisimdb/filesystem persistence (assemblyline + assail + assault)
- [x] VerisimDB hexad persistence: assemblyline aggregate reports stored as hexads
- [x] Fixed pre-existing test failures (migration_metrics field in test fixtures)
- [ ] verisimdb HTTP API integration: push hexads via REST (awaiting VerisimDB API stabilisation)

---

## v2.2.0 — Intelligence Layer

**Theme: Reduce false positives via context-aware reasoning**

- [ ] Context-fact generation in kanren (~10 rules for FP suppression)
- [ ] Hypatia feedback loop via PanLL for cross-project learning
- [ ] Export kanren facts as Logtalk predicates for hypatia
- [ ] Echidnabot proof verification of scan claims

---

## v2.3.0 — Constraint Sets & Advanced Stress

**Theme: Composable stress profiles**

- [ ] YAML-based constraint set definitions
- [ ] Multi-axis simultaneous attacks (not just sequential)
- [ ] Built-in profiles: production-spike, memory-leak, disk-full, network-partition, thundering-herd
- [ ] Custom profile authoring with intensity controls
- [ ] Profile composition (combine profiles)

---

## v3.0.0 — Public Release

**Theme: crates.io publication and ecosystem maturity**

- [ ] Publish to crates.io
- [ ] Pre-built binaries for Linux, macOS, Windows
- [ ] Shell completions (bash, zsh, fish, nushell)
- [ ] Man page generation
- [ ] SBOM generation
- [ ] Reproducible builds
- [ ] User guide (beyond README)
- [ ] Property-based testing (proptest)

---

## Long-Range Vision

See [VISION.md](VISION.md) for speculative future directions:

- Sensor/actuator integration
- Physical system modelling
- Digital twin stress testing
- Chapel metalayer for distributed analysis

---

## Authors

- **Concept & Design:** Jonathan D.A. Jewell
- **Initial Implementation:** Claude (Anthropic) + Jonathan D.A. Jewell
- **Date:** 2026-02-06 (started), ongoing
