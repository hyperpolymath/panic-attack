<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-03-07 -->

# panic-attack — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              SECURITY TESTER            │
                        │        (CLI, TUI, GUI, CI Hook)         │
                        └───────────────────┬─────────────────────┘
                                            │ Command / Spec
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           PANIC-ATTACK CORE             │
                        │    (Orchestration, Reports, Wiring)     │
                        └──────┬──────────┬──────────┬────────────┘
                               │          │          │
                               ▼          ▼          ▼
              ┌─────────────────┐  ┌────────────┐  ┌──────────────────────┐
              │ ANALYSIS LAYER  │  │ ATTACK     │  │ INFRASTRUCTURE       │
              │ - Assail (47L)  │  │ LAYER      │  │ - Assemblyline       │
              │ - kanren Logic  │  │ - 6-Axis   │  │ - Notify Pipeline    │
              │ - Taint/XLang   │  │ - Ambush   │  │ - Attestation Chain  │
              │ - Signatures    │  │ - Amuck    │  │ - i18n (10 langs)    │
              │ - Patterns      │  │ - Abduct   │  │ - VerisimDB Storage  │
              └────────┬────────┘  └─────┬──────┘  └──────────┬───────────┘
                       │                 │                     │
                       └────────┬────────┘                     │
                                ▼                              ▼
              ┌─────────────────────────────────┐  ┌──────────────────────┐
              │       TARGET PROGRAM            │  │ FLEET INTEGRATION    │
              │  (47 languages supported)       │  │ - Panicbot (PA001+) │
              └─────────────────────────────────┘  │ - Hypatia / PanLL   │
                                                   │ - Diagnostics       │
              ┌─────────────────────────────────┐  └──────────────────────┘
              │       MASS-PANIC LAYER           │
              │  Imaging (fNIRS-style health)    │
              │  Temporal (VeriSimDB snapshots)   │
              │  Chapel (multi-machine distrib.)  │
              └─────────────────────────────────┘
              ┌─────────────────────────────────┐
              │       REPORTING & OUTPUT         │
              │  JSON / YAML / Nickel / SARIF    │
              │  A2ML / PanLL / TUI / GUI        │
              │  Diff / Adjudicate / Axial       │
              └─────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE CAPABILITIES
  Assail Static Analysis            ██████████ 100%    47 languages, 20 categories
  Multi-Axis Stress Testing         ██████████ 100%    6 axes (CPU, Mem, Disk, etc)
  miniKanren Logic Engine           ██████████ 100%    Taint, cross-lang, strategies
  Ambush / Amuck / Abduct           ██████████ 100%    Advanced workflows stable
  Signature Detection Engine        ██████████ 100%    miniKanren-based inference

REPORTING & UI
  JSON/YAML/Nickel/SARIF Reports    ██████████ 100%    All 4 formats working
  TUI / GUI Dashboard               ████████░░  80%    Report browsing verified
  Diff / Adjudicate / Axial         ██████████ 100%    Campaign tools stable
  A2ML Bundle Import/Export         ██████████ 100%    Schema-versioned, attestation
  PanLL Event-Chain Export          ██████████ 100%    DAW-style timeline export
  PanLL Imaging Export              ██████████ 100%    panll.system-image.v0
  PanLL Temporal Export             ██████████ 100%    panll.temporal-diff.v0

MASS-PANIC
  System Health Imaging             ██████████ 100%    fNIRS-style risk map + edges
  Temporal Navigation               ██████████ 100%    VeriSimDB snapshots + diff
  Chapel Distributed Layer          ██████████ 100%    coforall + locales + multi-mode

BATCH & PIPELINE
  Assemblyline (rayon + BLAKE3)     ██████████ 100%    152 repos/49s, incremental 18.8s
  Notification Pipeline             ██████████ 100%    Markdown, critical-only, issues
  Cryptographic Attestation         ██████████ 100%    Intent → evidence → seal chain
  i18n Support (10 languages)       ██████████ 100%    ISO 639-1, compile-time safe

INTEGRATION
  Panicbot (gitbot-fleet)           ██████████ 100%    PA001–PA020, JSON contract
  Diagnostics (self-check)          ██████████ 100%    Version, fleet, attestation
  VerisimDB Storage                 ██████░░░░  60%    File I/O works, API planned
  Hypatia Pipeline                  ████░░░░░░  40%    Env var watcher, no kanren export

REPO INFRASTRUCTURE
  Justfile Automation               ██████████ 100%    build/test/readiness/lint/install
  .machine_readable/                ██████████ 100%    STATE/ECOSYSTEM/META + directives
  Test Suite                        ██████████ 100%    196 tests, 0 failures
  Readiness Tests (CRG)             ██████████ 100%    18 tests: D(4) C(10) B(4)

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            █████████░  ~97%   v2.1.0 Stable
```

## Key Dependencies

```
Assail (47L) ───► kanren Logic ───► Taint/XLang ───► Weak Points
     │                │                                    │
     ▼                ▼                                    ▼
Assemblyline ──► Notify Pipeline ──► GitHub Issues    Panicbot (PA001–PA020)
     │                │                                    │
     ▼                ▼                                    ▼
BLAKE3 Cache ──► VerisimDB Store ──► PanLL Export     Fleet FindingSet
     │                │                                    │
     ▼                ▼                                    ▼
Imaging ────────► Temporal ─────────► Chapel          System Image
(fNIRS map)       (snapshots)         (multi-machine)  (health portrait)
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
