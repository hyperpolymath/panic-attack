<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# Codebase Annotation Map

This document annotates the panic-attack codebase at an architectural level so maintainers can
trace data flow, intent, and operational boundaries across modules.

## 1. Execution Topology

- `src/main.rs`
  - Owns CLI contract and command dispatch.
  - Converts `clap` arguments into stable internal configs.
  - Persists reports and decides user-facing output behavior.
- `src/lib.rs`
  - Public module surface used by tests and external consumers.
  - Keeps module-level integration boundaries explicit.

## 2. Analysis Pipeline

- `src/assail/`
  - Static source analysis over multiple language families.
  - Produces `AssailReport` with weak points, recommendations, dependency graph, and taint matrix.
  - `src/assail/analyzer.rs`: decode + language-dispatch pipeline, framework detection, dependency/taint overlays.
  - `src/assail/patterns.rs`: language/framework attack pattern catalog used by dynamic execution.
- `src/attack/`
  - Dynamic axis execution (`cpu`, `memory`, `disk`, `network`, `concurrency`, `time`).
  - Handles probe mode and fallback behavior for unsupported target flags.
  - `src/attack/executor.rs`: strategy selection, timeout handling, crash/signature extraction, probe-aware skip logic.
  - `src/attack/profile.rs`: user profile ingestion (`json`/`yaml`) for common and per-axis args.
- `src/ambush/`
  - Timeline-driven ambient stress orchestration.
  - Coordinates concurrent stressors with optional DAW-like event scheduling.

## 3. Mutation and Isolation Surfaces

- `src/amuck/mod.rs`
  - Controlled mutation-combination runner.
  - Writes per-combo artifacts and optional command outcomes.
  - Never mutates target in place.
- `src/abduct/mod.rs`
  - Isolated copy workspace and readonly lock-down.
  - Optional dependency-neighborhood inclusion.
  - mtime shifting and time metadata export for delayed-trigger experiments.

## 4. Campaign Reasoning and Observation

- `src/adjudicate/mod.rs`
  - Aggregates `assault`, `amuck`, `abduct` artifacts.
  - Asserts normalized facts then applies compact inference rules.
  - Emits explainable campaign verdict (`pass`/`warn`/`fail`) plus priorities.
- `src/audience/mod.rs`
  - Observes target reactions from execution output and stored report artifacts.
  - Supports head/tail excerpts, exact/fuzzy pattern matches (`grep`/`agrep`), aspell, i18n.
  - Exports JSON + Markdown and optional Pandoc conversion.

## 5. Logic and Knowledge Layers

- `src/kanren/`
  - miniKanren-inspired term/fact/rule engine.
  - Bridges static findings to derived facts via forward chaining.
  - `src/kanren/core.rs`: unification, substitution, fact DB, fixpoint forward-chaining.
  - `src/kanren/taint.rs`: source/sink extraction and taint-propagation rule loading.
  - `src/kanren/crosslang.rs`: cross-language interaction facts and boundary-risk inference.
  - `src/kanren/strategy.rs`: risk-weighted file ordering heuristics for verbose assail output.
  - `src/kanren/rules.rs`: external rule-catalog loading and Nickel export.
- `src/signatures/`
  - Crash-signature detection and rule sets for known vulnerability classes.

## 6. Reporting and Storage

- `src/report/`
  - Structured formatters, diff tools, TUI/GUI views, and serializers.
  - Main conversion point for report presentation concerns.
  - `src/report/generator.rs`: assault report synthesis and robustness scoring heuristics.
  - `src/report/formatter.rs`: summary/accordion/dashboard/matrix terminal renderers.
  - `src/report/diff.rs`: human-readable report delta generation for regression review.
  - `src/report/output.rs`: JSON/YAML/Nickel serialization contracts.
- `src/storage/mod.rs`
  - Multi-target persistence logic (filesystem and VerisimDB-style cache paths).

## 7. Manifest and Integration

- `src/a2ml/mod.rs`
  - Minimal A2ML parser for AI manifest ingestion.
  - Nickel exporter for config interoperability.
  - Includes schema-versioned A2ML report bundle import/export for assail/attack/assault/ambush/amuck/abduct/adjudicate/audience.
- `src/panll/mod.rs`
  - PanLL event-chain export adapter.

## 8. Cross-Cutting Contracts

- Error strategy:
  - `anyhow` with contextualized errors at IO/process boundaries.
- Serialization strategy:
  - `serde` and JSON-first interchange, with YAML/Nickel where relevant.
- Safety strategy:
  - Copy-first workflows for destructive experimentation (`amuck`, `abduct`).
  - Timeouts on process execution paths to avoid hanging campaigns.

## 9. Extension Points

- Add new inference rules:
  - `src/adjudicate/mod.rs` for campaign-level verdict logic.
  - `src/kanren/` for deeper relational inference.
- Add new observation signals:
  - `src/audience/mod.rs::detect_signals`.
- Add new mutation primitives:
  - `src/amuck/mod.rs::MutationOperation`.
- Add new isolation semantics:
  - `src/abduct/mod.rs` dependency scope and workspace policies.

## 10. Annotation Conventions Used

- Module docs describe responsibility boundaries.
- Function comments explain non-obvious decisions and invariants.
- Export docs highlight contract shape for downstream tooling.
