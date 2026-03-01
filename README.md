# panic-attack

<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

[![CI](https://github.com/hyperpolymath/panic-attacker/workflows/Rust%20CI/badge.svg)](https://github.com/hyperpolymath/panic-attacker/actions/workflows/rust-ci.yml)
[![Security Audit](https://github.com/hyperpolymath/panic-attacker/workflows/Security%20Audit/badge.svg)](https://github.com/hyperpolymath/panic-attacker/actions/workflows/cargo-audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hyperpolymath/panic-attacker/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hyperpolymath/panic-attacker)
[![codecov](https://codecov.io/gh/hyperpolymath/panic-attacker/branch/main/graph/badge.svg)](https://codecov.io/gh/hyperpolymath/panic-attacker)
[![License: PMPL](https://img.shields.io/badge/License-PMPL--1.0--or--later-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.0-blue)](Cargo.toml)

Stress testing and bug signature detection for source code and binaries.
47 languages. 6 attack axes. Logic-based inference.

---

## Tier 1: Regular Use

**panic-attack is a CLI tool.** Point it at a file or directory and it tells you what's dangerous.

### Install

```bash
cargo install --path .
# or
cargo build --release && cp target/release/panic-attack ~/.local/bin/
```

### Scan a file

```bash
panic-attack assail ./src/main.rs
```

### Scan a project

```bash
panic-attack assail /path/to/project --verbose
```

### Save a report

```bash
panic-attack assail ./my-project --output report.json
panic-attack assail ./my-project --output report.sarif --output-format sarif
```

### What it detects

Static analysis across **47 languages** (Rust, C/C++, Go, Python, JavaScript, Elixir, Erlang, Gleam, ReScript, OCaml, Haskell, Idris, Lean, Agda, Zig, Ada, Julia, Shell, and 29 more) covering **20 weak point categories**:

- Unsafe code, raw pointer casts, transmute
- Panic paths, unwrap/expect density
- Command injection (`system()`, `exec.Command`, `os.system`)
- Unsafe deserialization (`pickle.load`, `JSON.parseExn`)
- DOM injection (`innerHTML`, `dangerouslySetInnerHTML`)
- Hardcoded secrets, path traversal, insecure protocols
- FFI boundary risks, atom exhaustion (BEAM)
- Resource leaks, deadlock potential, race conditions

Every weak point includes the file path, severity (Critical/High/Medium/Low), and recommended attack axis.

### Stress test a binary

```bash
# Single axis
panic-attack attack ./my-program --axis memory --intensity heavy --duration 30

# Full assault (static analysis + all 6 axes)
panic-attack assault ./my-program --output assault-report.json

# Run binary under ambient stress (doesn't need special flags)
panic-attack ambush ./my-program --axes cpu,memory
```

**6 attack axes:** CPU, Memory, Disk, Network, Concurrency, Time.

### Mutation testing

```bash
# Mutate a file with dangerous combinations, run checker on each variant
panic-attack amuck ./src/main.rs --preset dangerous --exec-program rustc --exec-arg {file}
```

### Isolate and time-skew

```bash
# Copy target + dependencies, lock read-only, age timestamps by 3 weeks
panic-attack abduct ./src/main.rs --scope direct --mtime-offset-days 21
```

### Review results

```bash
panic-attack report assault-report.json                   # Terminal summary
panic-attack report assault-report.json --report-view dashboard  # Dashboard view
panic-attack tui assault-report.json                       # Interactive TUI
panic-attack gui assault-report.json                       # GUI (egui)
panic-attack diff report-a.json report-b.json             # Compare two runs
```

---

## Tier 2: Workflow Integration

**panic-attack in CI/CD pipelines, batch scanning, and automated reporting.**

### SARIF output for GitHub Security tab

```bash
panic-attack assail ./my-project --output-format sarif --output results.sarif
```

Upload `results.sarif` to GitHub Code Scanning via the `github/codeql-action/upload-sarif` action.

### Assemblyline: batch-scan a directory of repos

```bash
# Scan all git repos in a directory
panic-attack assemblyline /path/to/repos/

# Only show repos with findings
panic-attack assemblyline /path/to/repos/ --findings-only

# Save aggregate report
panic-attack assemblyline /path/to/repos/ --output sweep-report.json --min-findings 3
```

Output is a sorted table (riskiest repos first) plus optional JSON with per-repo breakdowns.

### Campaign verdicts

Aggregate results from multiple tool runs into a single expert-system verdict:

```bash
panic-attack adjudicate reports/assault-a.json reports/amuck-a.json reports/abduct-a.json \
  --output campaign-verdict.json
```

### Observe tool reactions

Watch how programs behave under stress and search output for patterns:

```bash
panic-attack axial ./src/main.rs --report reports/amuck-a.json --grep "panic" --head 30
```

### Notification pipeline

```bash
# Generate annotated markdown summary of assemblyline findings
panic-attack notify sweep-report.json --output findings.md

# Only include repos with critical findings
panic-attack notify sweep-report.json --output findings.md --critical-only

# Create GitHub issues for repos with critical findings
panic-attack notify sweep-report.json --output findings.md --create-issues --github-owner hyperpolymath
```

### A2ML and PanLL export

```bash
# Export to AI manifest bundle
panic-attack a2ml-export --kind assail report.json --output report.a2ml

# Export to PanLL event-chain model
panic-attack panll assault-report.json --output event-chain.json
```

### Output formats

`--output-format` accepts: `json` (default), `yaml`, `nickel`, `sarif`.

### Diagnostics

```bash
# Verify Hypatia/gitbot-fleet/panicbot readiness
panic-attack diagnostics
```

### Readiness tests (CRG grades)

```bash
# Run machine-verifiable Component Readiness Grade tests
just readiness

# Summary: pass/fail count per grade
just readiness-summary
```

Grade D = runs without crashing, C = correct output, B = edge cases handled.

---

## Tier 3: At Scale

**Large-scale scanning, distributed analysis, and ecosystem integration. These are optional layers — panic-attack works perfectly without them.**

### VerisimDB persistence

Store scan results for trending, diffing, and cross-project analysis:

```bash
# Auto-store via manifest configuration
panic-attack assault ./my-program --store ./verisimdb-data/

# Diff the latest two stored reports
panic-attack diff
```

Storage modes (filesystem, verisimdb) are configured in `AI.a2ml`.

### Assemblyline at scale

For 500+ repos, `assemblyline` parallelises across all available cores:

- **Rayon parallelism**: 17.7x speedup (141 repos in 39.9s vs ~705s sequential)
- **BLAKE3 fingerprinting**: Hash source files, skip unchanged repos on re-scan
- **Incremental checkpointing**: Resume interrupted sweeps (planned)
- **Delta reporting**: "What's new/fixed since last run" (planned)

### Chapel metalayer (planned)

A parallel orchestration layer for cross-repo analysis:

- Parallel assail across thousands of repos via Chapel `coforall`
- Cross-repo taint analysis (FFI chains spanning multiple projects)
- Distributed kanren reasoning across the entire codebase
- Load-balanced campaign execution

See `docs/` for design documents. Chapel is strictly optional — the core tool never depends on it.

### PanLL visualisation

For interactive visualisation, dashboarding, and extended analysis, use panic-attack as part of [PanLL](https://github.com/hyperpolymath/panll) — the three-pane mission control that can ingest panic-attack reports as event-chain models. Export with `panic-attack panll report.json` and load the result into PanLL's Pane-W for visual triage.

### Integration points

| System | Integration | Status |
|--------|-------------|--------|
| **Hypatia** | Feed kanren facts as Logtalk predicates | Planned |
| **gitbot-fleet** | Trigger scans via repository_dispatch | Hooks wired |
| **VerisimDB** | Store results as hexads | File I/O works, API planned |
| **PanLL** | Export event-chain models | Working |
| **GitHub Security** | SARIF upload | Working |

---

## Architecture

```
src/
├── main.rs              # CLI (clap) — 20 subcommands
├── lib.rs               # Library API
├── types.rs             # Core types (47 languages, 20 categories)
├── assail/              # Static analysis engine
│   ├── analyzer.rs      # Per-file language detection + pattern matching
│   └── patterns.rs      # Language-specific attack pattern library
├── kanren/              # miniKanren logic engine
│   ├── core.rs          # Unification, substitution, fact DB
│   ├── taint.rs         # Source-to-sink taint analysis
│   ├── crosslang.rs     # FFI boundary vulnerability chains
│   └── strategy.rs      # Risk-weighted search prioritisation
├── attack/              # 6-axis stress testing
├── signatures/          # Bug signature detection (use-after-free, deadlock, etc.)
├── report/              # Output (JSON, YAML, Nickel, SARIF, TUI, GUI)
├── assemblyline.rs      # Batch scanning with rayon + BLAKE3
├── notify.rs            # Designer notification pipeline
├── ambush/              # Ambient stressors + DAW timeline
├── amuck/               # Mutation combinations
├── abduct/              # Isolation + time-skew
├── adjudicate/          # Campaign verdict aggregation
├── axial/               # Reaction observation
├── a2ml/                # AI manifest protocol
├── attestation/         # Cryptographic attestation chain
├── panll/               # PanLL event-chain export
├── storage/             # Filesystem + VerisimDB persistence
├── i18n/                # Multi-language support (ISO 639-1)
└── diagnostics.rs       # Self-check for Hypatia/gitbot-fleet
```

## All subcommands

| Command | What it does |
|---------|-------------|
| `assail` | Static analysis on a file or directory |
| `attack` | Single-axis stress test on a binary |
| `assault` | Combined assail + multi-axis attacks |
| `ambush` | Run binary under ambient stressors |
| `amuck` | Mutation testing with preset/custom combinations |
| `abduct` | Isolate file + dependencies with time-skew |
| `adjudicate` | Aggregate multiple reports into campaign verdict |
| `axial` | Observe target reactions from tool outputs |
| `assemblyline` | Batch-scan a directory of repos |
| `analyze` | Detect bug signatures from crash reports |
| `report` | Render a saved report (summary/dashboard/matrix) |
| `tui` | Interactive terminal UI for reports |
| `gui` | GUI viewer for reports (egui) |
| `diff` | Compare two reports |
| `manifest` | Render AI manifest as Nickel |
| `a2ml-export` | Convert report to A2ML bundle |
| `a2ml-import` | Convert A2ML bundle to JSON |
| `panll` | Export as PanLL event-chain model |
| `notify` | Generate annotated finding summaries + GitHub issues |
| `diagnostics` | Self-check for CI/CD visibility |

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full development plan and [TOPOLOGY.md](TOPOLOGY.md) for the architecture diagram.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Palimpsest Meta-Public License v1.0 or later](LICENSE) (SPDX: `PMPL-1.0-or-later`)

## Author

**Jonathan D.A. Jewell** <j.d.a.jewell@open.ac.uk>

---

**Version**: 2.0.0 | **MSRV**: 1.85.0 | **Languages**: 47 | **Attack Axes**: 6
