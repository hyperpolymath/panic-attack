<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# Ambush Timeline & Event-Chain Plan (DAW-style)

This document captures the long-range design for a DAW-like timeline model that
drives `panic-attack` ambush runs. It is intentionally staged so the tool stays
simple while enabling deeper event-chain modelling (for panll integration).

## Goals

- Keep the default CLI simple (single command, predictable output).
- Add a DAW-style timeline that schedules stressors by axis over time.
- Model event chains with conditions and Theory of Constraints (ToC) controls.
- Export/import models for panll without forking core logic.
- Work cross-platform (Linux/macOS/BSD/Windows, RISC-V, Minix) via fallback
  stressors and optional OS-specific backends.

## Non-Goals (for MVP)

- No mandatory kernel integrations.
- No blocking dependency on privileged operations (cgroups, PF, WFP).
- No requirement to modify the target program.

## Terminology

- **Axis**: stress dimension (cpu/memory/disk/network/concurrency/time).
- **Track**: an axis lane on the timeline.
- **Clip/Event**: a scheduled stressor with params + duration.
- **Automation**: condition-driven changes (thresholds, curves).
- **Event Chain**: causal graph of events and transitions.
- **Constraint**: the bottleneck (ToC) that governs overall scheduling.

## Phase 1 (MVP) — Timeline Scheduler

**Deliverable:** `panic-attack ambush --timeline timeline.yaml`

**Capabilities**
- Run the target under ambient stressors (existing ambush).
- Timeline file schedules axis stressors with `at` + `for`.
- Events are independent; overlapping events run concurrently.
- Output is a standard assault report + timeline metadata.

**Example YAML**
```yaml
program: ./target/release/my-program
duration: 120s
tracks:
  - axis: cpu
    events:
      - at: 0s
        for: 30s
        intensity: light
      - at: 30s
        for: 30s
        intensity: heavy
  - axis: memory
    events:
      - at: 10s
        for: 40s
        intensity: medium
  - axis: disk
    events:
      - at: 60s
        for: 20s
        intensity: light
```

**CLI sketch**
```
panic-attack ambush ./my-program --timeline timeline.yaml
panic-attack ambush ./my-program --timeline timeline.yaml --source ./src
```

## Phase 2 — Conditions & Event Chains

**Capabilities**
- Events may have conditions:
  - `start_when: { crashes >= 1 }`
  - `start_when: { cpu_load > 0.7 }`
- Event chains allow `eventA -> eventB` dependencies.
- Conditional branching based on runtime signals.

**Conceptual schema**
```yaml
events:
  - id: spike-1
    axis: cpu
    at: 0s
    for: 20s
    intensity: heavy
  - id: memory-followup
    axis: memory
    for: 30s
    intensity: medium
    start_when:
      event: spike-1
      outcome: crash
```

## Phase 3 — Theory of Constraints (ToC)

**Capabilities**
- Define a constraint axis (bottleneck).
- Subordinate other stressors when the constraint is saturated.
- Apply ToC rules such as:
  - "Memory is constraint; throttle CPU when memory pressure > 80%."
  - "Disk is constraint; cap concurrency when IO latency spikes."

**Sketch**
```yaml
constraints:
  bottleneck: memory
  subordinate:
    cpu:
      if: { memory_pressure > 0.8 }
      action: { intensity: light }
```

## Phase 4 — Panll Integration

**Direction A (export):**
- Emit panll-compatible event chain + constraints.
- Use A2ML/Nickel to encode chain metadata alongside assault reports.

**Direction B (import):**
- Accept panll models and execute them as timelines.

**Decision point:** choose which direction first (export or import).

## Data Model (Draft)

Core structures:
- `Timeline`
  - `program`, `duration`, `tracks`
- `Track`
  - `axis`, `events`
- `Event`
  - `id`, `at`, `for`, `intensity`, `args`, `conditions`
- `Constraint`
  - `bottleneck`, `rules`

Serialization targets: JSON, YAML, Nickel.

## Execution Semantics (Draft)

- Timeline time is wall-clock.
- Events can overlap (parallel stressors).
- Conditions are evaluated at a fixed cadence (e.g., 500ms).
- Failures are recorded in a timeline segment.
- Report preserves both “global” assault metrics and timeline segment metrics.

## Platform Strategy (Cross-OS, RISC-V, Minix)

**Portable baseline (always available):**
- Internal stressors (CPU loops, memory alloc, disk temp I/O, local TCP).

**Optional OS backends (pluggable):**
- Linux: cgroups + `tc`.
- macOS: `taskpolicy`, `ulimit`, `pf/dummynet`.
- BSD: `rctl` + `pf/dummynet`.
- Windows: Job Objects + WFP.
- Minix/RISC-V: baseline stressors only unless platform hooks exist.

Execution should autodetect available backend and fall back to portable mode.

## Reporting & Storage

- Attach timeline metadata to assault report.
- Export timeline + event chain summary to Nickel/A2ML.
- Preserve timeline-specific metrics for diffing.

## Implementation Checklist

Phase 1:
- [ ] Add timeline schema + parser.
- [ ] Add `ambush --timeline` CLI flag.
- [ ] Run scheduled stressors concurrently.
- [ ] Capture per-event outputs in the report.

Phase 2:
- [ ] Add conditions (`start_when`, `stop_when`).
- [ ] Add event graph dependencies.

Phase 3:
- [ ] Add ToC engine (bottleneck + subordination).

Phase 4:
- [ ] Panll export/import adapters.

---

Status: Draft (2026-02-09). This document is the source of truth for the
timeline/event-chain direction and should be updated as implementation lands.
