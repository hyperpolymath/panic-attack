<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk> -->

# panic-attack Component Readiness Assessment

**Standard:** [Component Readiness Grades (CRG) v1.0](https://github.com/hyperpolymath/standards/tree/main/component-readiness-grades)
**Assessed:** 2026-03-01
**Assessor:** Jonathan D.A. Jewell + Claude Opus 4.6

## Summary

| Component           | Grade | Release Stage      | Evidence Summary                                                    |
|---------------------|-------|--------------------|---------------------------------------------------------------------|
| `assail`            | C     | Beta               | Dogfooded on self; 22 findings. Tested on 141 repos via assemblyline. |
| `attack`            | D     | Alpha              | Works on example binary (cpu axis). Other axes not tested on diverse targets. |
| `assault`           | D     | Alpha              | Works on self + example binary. Full multi-axis only tested on one target. |
| `ambush`            | D     | Alpha              | Works with and without timeline. Timeline events skip when target exits fast (correct behaviour). |
| `amuck`             | D     | Alpha              | Generates mutated files. Preset light works. Dangerous preset and exec-program untested on diverse targets. |
| `abduct`            | D     | Alpha              | File isolation + mtime-shift works. Time-skewing (frozen/slow modes) and exec-program untested on diverse targets. |
| `adjudicate`        | D     | Alpha              | Aggregates 2+ reports with expert-system verdict. Only tested on panic-attack's own reports. |
| `axial`             | D     | Alpha              | Observation with --report works. Exec-program observation works. grep/agrep/aspell/pandoc untested. |
| `analyze`           | C     | Beta               | Detects UseAfterFree, NullPointerDeref from crash reports. Both rule evaluation and stderr matching work on synthetic data. |
| `report`            | C     | Beta               | Renders assault reports in terminal. Works on self-generated reports. All view modes available. |
| `tui`               | E     | Pre-alpha           | Initialises but requires real terminal. Cannot be tested in CI/headless. No smoke test possible. |
| `gui`               | E     | Pre-alpha           | Initialises but requires display server. Cannot be tested in CI/headless. |
| `diff`              | C     | Beta               | Compares two reports correctly. Shows robustness delta, weak point delta, per-axis changes. |
| `manifest`          | C     | Beta               | Exports AI.a2ml to Nickel format. Works on self. Output is valid Nickel. |
| `a2ml-export`       | C     | Beta               | Round-trips assault report to A2ML bundle. Works on self-generated reports. |
| `a2ml-import`       | C     | Beta               | Round-trips A2ML bundle back to JSON. Verified round-trip integrity. |
| `panll`             | C     | Beta               | Exports event-chain with real constraints. 2 critical WPs, attack events extracted correctly. |
| `assemblyline`      | C     | Beta               | Scanned 141 repos in parallel (rayon). BLAKE3 fingerprinting. 3448 findings, 254 critical. |
| `diagnostics`       | C     | Beta               | Reports version, manifest, directories, integrations. Works on self. |
| `help`              | C     | Beta               | Lists all 19 subcommands with descriptions and options. |

## Overall Project Readiness

- **Components at C (Beta) or above:** 14/19 (74%)
- **Components at D (Alpha):** 5/19 (26%)
- **Components at E (Pre-alpha):** 2/19 (11%)
- **Components at F (Reject):** 0/19 (0%)
- **Minimum project-wide grade:** E (tui, gui)
- **Weighted assessment:** The project is **Beta-quality** for its core workflow (assail/assault/report/assemblyline) and **Alpha-quality** for the full dynamic testing suite.

## Detailed Assessment

### `assail` — Static Analysis Engine (Grade: C)

**Evidence:**
- Successfully scans its own codebase: 22 weak points detected (2 critical, 9 high, 10 medium, 1 low)
- Verbose mode shows per-file risk breakdown with 40 files ranked
- Logic engine produces 125 facts and 9 derived facts
- JSON output is well-formed and machine-readable
- Exercised across 141 repos via assemblyline (3448 total findings)
- 47 language analyzers registered

**Known limitations:**
- Framework detection has false positives (reports Phoenix/Ecto/Cowboy/OTP on a pure Rust project)
- Some patterns detect their own search strings as findings (e.g., "transmute" in analyzer.rs)

**Promotion path to B:** Test on 6 diverse projects in different languages (not just Rust repos via assemblyline).

### `attack` — Single Axis Stress Test (Grade: D)

**Evidence:**
- CPU axis works on example binary (exits cleanly, 0 crashes)
- Report output is structured and correct

**Known limitations:**
- Only tested on one binary with one axis
- Memory/disk/network/concurrency/time axes not individually validated
- No test against a program that actually crashes under stress

**Promotion path to C:** Test all 6 axes on panic-attack's own test binaries and the vulnerable_program example.

### `assault` — Combined Static + Dynamic (Grade: D)

**Evidence:**
- Combines assail + attack successfully
- Produces structured AssaultReport with all sections
- VerisimDB hexad storage works automatically
- Multi-format output (JSON, YAML, Nickel) works

**Known limitations:**
- Only tested with cpu axis (full multi-axis on self not validated in this session)
- Previous session ran full multi-axis; results were valid but only on one target

**Promotion path to C:** Run full multi-axis assault on panic-attack's own binary.

### `ambush` — Ambient Stress with Timeline (Grade: D)

**Evidence:**
- Works without timeline (falls back to standard attack flow)
- Timeline YAML parsing works correctly (4 events across 3 tracks)
- Timeline events are correctly scheduled with start offsets
- Events are correctly skipped when target exits before their start time

**Known limitations:**
- Timeline events only tested once; stressor threads for cpu/memory/concurrency verified but only in isolation
- No test with a long-running program that exercises the full timeline duration

**Promotion path to C:** Create a test binary that runs for 15+ seconds, run with the timeline spec, verify all events fire in sequence.

### `amuck` — File Mutation Testing (Grade: D)

**Evidence:**
- Light preset generates 1 mutated variant with prepend/append operations
- Output file written to runtime/amuck/
- JSON report correctly records operations applied

**Known limitations:**
- Dangerous preset not tested
- Custom spec file not tested
- exec-program integration not tested (compile and test mutated files)

**Promotion path to C:** Test dangerous preset, write a custom spec, and use exec-program to compile and test mutated variants of our own source files.

### `abduct` — File Isolation & Time-Skewing (Grade: D)

**Evidence:**
- Direct scope copies target + dependencies correctly
- mtime-offset-days shifts file timestamps
- Readonly lock is applied to copied files
- Workspace created in runtime/abduct/

**Known limitations:**
- frozen/slow time modes not tested
- virtual-now not tested
- exec-program integration not tested
- twohops/directory scope not tested

**Promotion path to C:** Test frozen time mode with exec-program on a binary that checks timestamps.

### `adjudicate` — Report Aggregation (Grade: D)

**Evidence:**
- Processes 2 assault reports correctly
- Expert-system verdict ("fail" based on critical weak points) is generated
- Rule hits documented with confidence scores
- Priorities extracted correctly

**Known limitations:**
- Only tested with assault reports; amuck/abduct report aggregation untested
- Only 2 reports aggregated; scaling untested
- Only one campaign pattern exercised (campaign_fail_on_high_signal)

**Promotion path to C:** Test with all 3 report types (assault, amuck, abduct) and with 5+ reports.

### `axial` — Target Reaction Observation (Grade: D)

**Evidence:**
- Report observation mode works (reads assault JSON, produces markdown)
- Exec-program mode works (runs binary, captures output)
- Markdown output is well-formatted

**Known limitations:**
- grep/agrep pattern matching not tested
- aspell integration not tested
- pandoc conversion not tested
- i18n (non-English output) not tested via this subcommand

**Promotion path to C:** Test grep patterns on stderr of a crashing program, test aspell on output text.

### `analyze` — Crash Report Analysis (Grade: C)

**Evidence:**
- Detects UseAfterFree from both rule evaluation (Alloc→Free→Use sequence) and stderr patterns
- Detects NullPointerDeref from SIGSEGV in signal field
- Confidence scores differentiated (0.85 rule-based, 0.95 stderr-based)
- Variable bindings reported in evidence (X_loc, X_loc2, X = heap_var)

**Known limitations:**
- Only synthetic crash reports tested (no real crash from running code)
- Deadlock, DataRace, MemoryLeak, BufferOverflow rules not exercised

**Promotion path to B:** Feed in real crash reports from at least 6 different crash scenarios (use ASAN/TSAN output from real C/Rust programs).

### `report` — Report Rendering (Grade: C)

**Evidence:**
- Renders full assault report in terminal with sections: assail, detail panel, attack results, signatures, assessment
- All view modes available via --report-view flag

**Promotion path to B:** Test rendering of reports from 6+ diverse projects.

### `tui` — Terminal UI (Grade: E)

**Evidence:**
- Code exists and compiles
- Attempts to initialize crossterm terminal but fails without a real TTY (os error 6)
- Cannot be smoke-tested in a headless/CI environment

**Promotion path to D:** Add a --dry-run flag or test harness that validates the report loading without needing a terminal.

### `gui` — Graphical UI (Grade: E)

**Evidence:**
- Code exists and compiles
- Times out (no display server in CLI context)
- eframe-based; requires Wayland/X11

**Promotion path to D:** Same as TUI — add headless validation mode.

### `diff` — Report Comparison (Grade: C)

**Evidence:**
- Correctly compares two reports: robustness delta, weak point delta, per-axis status changes
- Framework changes tracked
- Severity breakdown tracked (critical, high, medium, low)

**Promotion path to B:** Compare reports from 6+ diverse projects at different points in time.

### `manifest` — AI Manifest Export (Grade: C)

**Evidence:**
- Parses AI.a2ml and exports to Nickel format
- Output includes all manifest sections: version, project, canonical-locations, critical-invariants, lifecycle, tools, reports

**Promotion path to B:** Test on AI.a2ml files from 6+ different repos.

### `a2ml-export` / `a2ml-import` (Grade: C each)

**Evidence:**
- Round-trip verified: assault JSON → A2ML bundle → JSON
- Output file sizes match (3371 lines round-tripped)
- Kind discrimination works (--kind assault)

**Promotion path to B:** Test with all report kinds (assault, amuck, abduct) from 6+ projects.

### `panll` — PanLL Event-Chain Export (Grade: C)

**Evidence:**
- Exports event chain from assault report
- 2 constraints extracted from critical weak points
- Attack events correctly represented
- Summary includes weak points, crashes, robustness score

**Promotion path to B:** Test with reports from 6+ projects with varying numbers of findings.

### `assemblyline` — Batch Repo Scanning (Grade: C)

**Evidence:**
- Scanned 141 repos in parallel via rayon
- 3448 weak points found, 254 critical
- BLAKE3 fingerprinting computed for all repos
- Results sorted by risk (developer-ecosystem: 633, idaptik: 427, ...)
- Filters (--findings-only, --min-findings) work correctly

**Promotion path to B:** Run on 6+ different parent directories (different machines, different repo structures).

### `diagnostics` — Self-Diagnostics (Grade: C)

**Evidence:**
- Reports version, AI manifest status, directory existence, report cache counts
- Correctly identifies missing integration configs (Hypatia, gitbot-fleet)

**Promotion path to B:** Validate diagnostics output on 6+ repos with different configurations.

### `help` — Help Text (Grade: C)

**Evidence:**
- Lists all 19 subcommands with accurate descriptions
- Shows all global options
- Per-subcommand help available

**Promotion path to B:** Help is generic by nature; B/A grades apply once external users confirm the docs are clear.

## F-Grade Analysis

No components earned an F. Candidates considered and rejected:

- **tui/gui**: These are E, not F. They serve a real purpose (interactive report review) and are salvageable with a dry-run mode. No better alternative exists specifically for panic-attack reports.
- **axial**: Some features (aspell, pandoc) could be delegated to external tools, but the integrated observation + report correlation is unique to panic-attack. Not an F.

## Concerns and Maintenance Notes

1. **Framework detection false positives**: assail detects Elixir/Erlang frameworks (Phoenix, Ecto, OTP) on a pure Rust project. This should be gated on detected language.
2. **Self-detection**: The tool detects its own pattern-matching strings as vulnerabilities. Consider adding self-exclusion or annotation support.
3. **Timeline event scheduling**: The DAW-style timeline works but needs a long-running test target to exercise fully.
4. **amuck dangerous preset**: Untested. Could generate broken mutations that confuse users.
5. **abduct time modes**: frozen/slow modes are implemented but completely untested.
