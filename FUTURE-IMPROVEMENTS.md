<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

# Future Improvements: Insights from Scanning the Eclexia Compiler Toolchain

**Date:** 2026-02-08
**Author:** Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
**Context:** panic-attack v1.0.0, scanning Eclexia (10 crates, ~20,000 lines of Rust)

---

## Executive Summary

Scanning the Eclexia compiler toolchain with `panic-attack assail` exposed
several categories of false positives, misdetections, and missing features
that reduce the tool's signal-to-noise ratio on well-engineered Rust
codebases. This document captures the specific observations and proposes
concrete improvements, prioritised for implementation.

The core finding is that panic-attack currently treats all code uniformly --
test code is scored the same as production code, safe unwrap variants are
counted alongside unsafe ones, and severity ratings do not account for
language-specific safety guarantees. For a codebase like Eclexia with zero
unsafe blocks, zero production unwraps, and comprehensive error handling via
`Result<_, RuntimeError>`, the current output overstates risk significantly.

These improvements would benefit any Rust workspace scan, not just Eclexia.

---

## Completed Observations

The following observations were made during the Eclexia scan session:

1. **Eclexia profile:** 10 crates, ~20,000 lines of Rust, 0 unsafe blocks,
   0 production unwrap calls, full `Result`-based error handling with custom
   `RuntimeError` type and `?` propagation throughout.

2. **False positive rate:** The `builtins.rs` module was flagged with 96
   unwrap calls and 13 panic sites, all of which reside exclusively within
   `#[cfg(test)]` modules. This produced a "Medium" severity finding for a
   file with zero production panic paths.

3. **Framework misdetection:** panic-attack reported "WebServer" as the
   detected framework for pure compiler crates that perform zero I/O
   operations (no network, no HTTP, no filesystem serving).

4. **Safe unwrap variants counted as risks:** Calls to `.unwrap_or(1)`,
   `.unwrap_or_default()`, and `.unwrap_or_else(|| ...)` were counted
   toward the `unwrap_calls` metric. These are safe patterns that cannot
   panic and should not contribute to risk scoring.

5. **Severity not calibrated for Rust safety guarantees:** A crate with 0
   unsafe blocks, 0 production unwraps, and comprehensive `Result`
   propagation still received non-trivial risk scores due to allocation
   site counts alone.

6. **No workspace-level consolidation:** Scanning 10 crates individually
   produced 10 separate reports with no aggregate view of workspace health.

7. **No differential capability:** There is no way to compare a scan before
   and after a refactoring to show what improved or regressed.

8. **Allocation sites lack context:** The report stated "73 allocation
   sites" without distinguishing between `Vec::new()` (safe, bounded) and
   user-controlled allocations (potentially unbounded).

---

## Proposed Improvements

### 1. Test Code Exclusion

**Priority:** HIGH

**Problem:** panic-attack counts `unwrap()` and `panic!()` calls inside
`#[cfg(test)]` modules, `#[test]` functions, and files in `tests/`
directories as production panic paths. This produces false positives for
any well-tested codebase. In the Eclexia scan, 100% of the unwrap and
panic findings in `builtins.rs` (96 unwrap calls, 13 panic sites) were
test-only code, yet the file received a "Medium" severity rating.

**Proposed solution:**

- Parse `#[cfg(test)]` module boundaries and `#[test]` function boundaries
  in the Rust analyzer.
- Exclude files matching `tests/**`, `test_*.rs`, `*_test.rs` patterns.
- Report test code metrics separately (e.g., `test_unwrap_calls`) so they
  remain visible but do not affect severity scoring.
- Add a `--include-test-code` flag for users who want the current behaviour.

**Impact:** Eliminates the single largest source of false positives on
well-tested Rust codebases.

---

### 2. Framework Detection Accuracy

**Priority:** HIGH

**Problem:** panic-attack reports "WebServer" as the detected framework for
pure compiler crates with zero I/O operations. This is a misdetection that
undermines trust in the tool's output. The Eclexia crates have no HTTP
dependencies, no server bindings, and no network code.

**Proposed solution:**

- Revise framework detection heuristics to require evidence of actual I/O
  patterns (e.g., TCP listeners, HTTP handlers, route definitions), not
  just crate structure.
- Add a "None" or "CLI" framework classification for projects that do not
  match any framework pattern.
- Consider inspecting `Cargo.toml` dependencies as a signal: presence of
  `actix-web`, `axum`, `warp`, `rocket`, or `hyper` strongly indicates a
  web server; absence of these with presence of `clap`, `structopt`, or
  a `[[bin]]` target suggests a CLI tool.
- For library crates with no binary target and no I/O dependencies, default
  to "Library" rather than guessing a framework.

**Impact:** Prevents misleading framework labels that erode confidence in
the overall report.

---

### 3. Safe Unwrap Variant Distinction

**Priority:** HIGH

**Problem:** The Rust analyzer counts `.unwrap_or(value)`,
`.unwrap_or_default()`, and `.unwrap_or_else(|| ...)` toward the
`unwrap_calls` metric. These methods are safe alternatives to `.unwrap()`
that cannot panic -- they provide fallback values instead. Counting them as
risks conflates safe error handling with unsafe panic paths.

**Proposed solution:**

- Distinguish between panic-capable unwrap calls (`.unwrap()`,
  `.expect("...")`) and safe variants (`.unwrap_or(...)`,
  `.unwrap_or_default()`, `.unwrap_or_else(|| ...)`).
- Report safe variants in a separate metric (e.g., `safe_unwrap_calls`)
  that does not contribute to severity scoring.
- Optionally report the ratio of safe-to-unsafe unwraps as a code quality
  signal: a high ratio indicates disciplined error handling.

**Impact:** Improves accuracy of the core unwrap metric, which is one of
the primary signals in Rust analysis.

---

### 4. Language-Specific Severity Calibration

**Priority:** MEDIUM

**Problem:** For Rust codebases, 0 unsafe blocks combined with 0 production
unwraps represents an exceptionally strong safety posture. However,
panic-attack still assigns non-trivial risk scores based on allocation site
counts alone. A crate with zero ways to reach a panic path should be
classified as "clean" or "hardened," not flagged with residual risk.

**Proposed solution:**

- Introduce a "hardened" or "clean" severity tier for codebases that meet
  language-specific safety criteria.
- For Rust, the criteria would be: 0 unsafe blocks, 0 production
  `.unwrap()` / `.expect()` calls (excluding test code), and presence of
  `Result`-based error handling with `?` propagation.
- Allocation sites alone should not elevate severity. They should be
  reported as informational context, not risk indicators, unless combined
  with unsafe blocks or unbounded allocation patterns.
- Allow language-specific scoring profiles so that a Rust crate with no
  unsafe code is evaluated differently from a C program with manual memory
  management.

**Impact:** Reduces false severity inflation on well-engineered Rust
codebases and makes the severity metric more meaningful across languages.

---

### 5. Workspace-Level Consolidated Reporting

**Priority:** MEDIUM

**Problem:** When scanning a Cargo workspace with 10 crates, panic-attack
produces 10 independent reports with no aggregate view. Users must manually
collate results to understand workspace-level health. There is no way to
identify which crate contributes the most risk or how the workspace compares
overall to other projects.

**Proposed solution:**

- Detect Cargo workspaces (presence of `[workspace]` in root `Cargo.toml`)
  and automatically scan all member crates.
- Produce a consolidated report with:
  - Per-crate breakdowns (individual scores and findings).
  - Workspace-level totals (aggregate weak points, overall severity).
  - A "top offenders" summary listing the crates with the highest risk.
  - Shared dependency analysis (which dependencies appear across crates).
- Support `--workspace` flag for explicit workspace scanning.
- In JSON output, nest per-crate results under a `workspace` object with
  metadata about the workspace itself.

**Impact:** Enables meaningful assessment of multi-crate projects, which
represent the majority of non-trivial Rust codebases.

---

### 6. Differential Scanning (Before/After Comparison)

**Priority:** MEDIUM

**Problem:** There is no way to compare two scans to show what improved or
regressed between them. This limits the tool's usefulness in CI pipelines,
where the primary question is "did this change make things better or worse?"

**Proposed solution:**

- Add a `panic-attack diff <baseline.json> <current.json>` subcommand that
  compares two scan results.
- Output should show:
  - New findings (present in current but not baseline).
  - Resolved findings (present in baseline but not current).
  - Changed severity (findings that moved between severity tiers).
  - Net change in weak point count and severity score.
- Support exit codes for CI: exit 0 if no regressions, exit 1 if new
  findings or severity increases detected.
- Optionally accept a `--baseline` flag in the `assail` command to perform
  the comparison inline: `panic-attack assail . --baseline previous.json`.

**Impact:** Makes panic-attack viable as a CI gate that detects regressions
without requiring manual report comparison.

---

### 7. Allocation Site Context and Classification

**Priority:** MEDIUM

**Problem:** Reporting "73 allocation sites" without context is not
actionable. A `Vec::new()` in a function with bounded iteration is safe. A
`Vec::with_capacity(user_input)` is a potential denial-of-service vector.
The current report does not distinguish between these cases.

**Proposed solution:**

- Classify allocation sites into categories:
  - **Bounded:** Allocation size is a compile-time constant or derived from
    a bounded source (e.g., `Vec::with_capacity(256)`).
  - **Internally bounded:** Allocation depends on internal state that the
    program controls (e.g., `Vec::new()` in a loop with a fixed upper
    bound).
  - **User-controlled:** Allocation size depends on external input (e.g.,
    `Vec::with_capacity(header.length)`).
  - **Unknown:** Allocation size cannot be statically determined.
- Only flag user-controlled and unknown allocations as potential risk.
- Report bounded allocations as informational.

**Impact:** Transforms allocation site reporting from noise into a useful
signal for identifying actual denial-of-service vectors.

---

### 8. Resource Dimension Awareness for Domain-Specific Languages

**Priority:** LOW

**Problem:** Eclexia is a domain-specific language with first-class resource
types (energy, carbon, latency). Programs written in Eclexia manage
resource budgets as part of their core semantics. panic-attack has no
awareness of these domain-specific resource dimensions and therefore cannot
detect unbounded resource consumption patterns in Eclexia programs.

**Proposed solution:**

- Add an extensible resource dimension system that allows language-specific
  analyzers to define custom resource types beyond CPU/memory/disk/network.
- For Eclexia specifically, detect:
  - `@resource_constraint` blocks and verify they have bounded consumption.
  - `@solution` blocks and check that fallback paths exist.
  - Resource type declarations and flag any that lack upper bounds.
- Implement this as a plugin or analyzer extension rather than hard-coding
  Eclexia-specific logic into the core tool.
- Generalize the pattern: any language with resource annotations (Rust's
  `#[must_use]`, Ada's resource management, etc.) could benefit from
  similar awareness.

**Impact:** Extends panic-attack's value proposition to domain-specific
languages with resource semantics. Requires language-specific investment
but aligns with the long-term vision of universal constraint testing.

---

### 9. Pattern Detection for Safe Error Handling

**Priority:** LOW

**Problem:** panic-attack does not recognize structured error handling
patterns. A crate that consistently uses `Result<T, RuntimeError>` with
`?` propagation throughout its public API has a fundamentally different
risk profile from one that uses `.unwrap()` liberally. The current analysis
treats both the same.

**Proposed solution:**

- Detect and score the following safe error handling patterns:
  - `Result<T, E>` return types on public functions.
  - Consistent use of `?` operator for error propagation.
  - Custom error types with `From` implementations for error conversion.
  - `thiserror` or `anyhow` usage patterns.
- Introduce an "error handling maturity" metric:
  - **Level 0:** No structured error handling (raw panics).
  - **Level 1:** Partial `Result` usage with frequent `.unwrap()`.
  - **Level 2:** Consistent `Result` usage with occasional `.unwrap()`.
  - **Level 3:** Full `Result` propagation, custom error types, no
    production `.unwrap()` calls.
- Use this metric as a positive modifier on severity scoring: higher
  maturity should reduce overall severity.

**Impact:** Rewards disciplined error handling and produces more accurate
risk assessments for Rust codebases that invest in proper error management.

---

### 10. Configurable Severity Thresholds for CI

**Priority:** LOW

**Problem:** panic-attack produces severity ratings but does not support
project-specific pass/fail criteria. Different projects have different
standards -- a safety-critical system might require 0 unsafe blocks while
a prototype might tolerate higher risk. Without configurable thresholds,
CI integration requires external scripting to interpret results.

**Proposed solution:**

- Add a `[thresholds]` section to `panic-attacker.toml`:

  ```toml
  [thresholds]
  max_unsafe_blocks = 0
  max_production_unwraps = 5
  max_severity = "low"
  max_weak_points = 20
  require_error_handling_level = 2
  ```

- When thresholds are configured, `panic-attack assail` should produce a
  pass/fail verdict in addition to the detailed report.
- Exit code 0 for pass, exit code 1 for fail, with clear indication of
  which thresholds were violated.
- Support per-crate threshold overrides in workspace mode.
- Allow threshold inheritance: define workspace-level defaults with
  per-crate overrides for crates with special requirements.

**Impact:** Makes panic-attack directly usable as a CI gate without
external wrapper scripts, supporting project-specific quality standards.

---

## Implementation Notes

### Dependency on Existing Architecture

Improvements 1-4 (test code exclusion, framework detection, unwrap variant
distinction, and severity calibration) are modifications to the existing
Rust analyzer in `src/assail/mod.rs`. They can be implemented incrementally
without architectural changes.

Improvement 5 (workspace consolidation) requires a new scanning mode in
`src/main.rs` and a new report aggregation layer, but reuses the existing
per-crate scan logic.

Improvement 6 (differential scanning) is a new subcommand that operates on
JSON output files. It is independent of the scan engine and can be
implemented at any time.

Improvements 7-9 (allocation context, resource dimensions, error handling
patterns) require deeper static analysis capabilities. They should be
planned for post-v1.0 milestones.

Improvement 10 (configurable thresholds) extends the existing
`panic-attacker.toml` configuration and is straightforward to implement
once the metrics it depends on (from improvements 1-4) are accurate.

### Recommended Implementation Order

1. Test code exclusion (improvement 1) -- highest impact, lowest effort.
2. Safe unwrap variant distinction (improvement 3) -- high impact, low
   effort, same code area as improvement 1.
3. Framework detection accuracy (improvement 2) -- high impact, moderate
   effort.
4. Language-specific severity calibration (improvement 4) -- depends on
   improvements 1 and 3 being complete.
5. Workspace consolidation (improvement 5) -- independent track, can
   proceed in parallel with 1-4.
6. Differential scanning (improvement 6) -- independent track, high CI
   value.
7. Allocation site context (improvement 7) -- post-v1.0.
8. Error handling patterns (improvement 9) -- post-v1.0.
9. Configurable thresholds (improvement 10) -- depends on 1-4.
10. Resource dimension awareness (improvement 8) -- long-term.

### Relationship to Existing Roadmap

This document complements `ROADMAP.md` and `VISION.md`. The improvements
described here are specific, actionable findings from real-world usage,
whereas the roadmap covers broader feature milestones. Several items
overlap with planned roadmap work:

- Improvement 5 overlaps with the planned `sweep` subcommand.
- Improvement 6 overlaps with v0.8 "Comparative reports (diff two Assail
  runs)".
- Improvement 10 overlaps with v0.8 "Exit codes that CI can act on."

These improvements should be incorporated into the relevant roadmap
milestones rather than tracked separately.

---

## Authors

- **Analysis and writing:** Jonathan D.A. Jewell
- **Scan session:** 2026-02-08
- **Tool version:** panic-attack v1.0.0
