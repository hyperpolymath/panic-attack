# panic-attack: Technical Design

> **Note**: This document describes the original design from 2026-02-07. The tool has since
> evolved significantly (47 languages, miniKanren engine, SARIF, attestation, panicbot integration).
> See `.claude/CLAUDE.md` for current architecture and `ROADMAP.md` for current status.

## Motivation

Modern software testing often focuses on either:
1. **Fuzzing**: Random input generation (afl, libFuzzer)
2. **Property Testing**: Verification of invariants (QuickCheck, PropTest)
3. **Static Analysis**: Code inspection without execution (Clippy, CodeQL)

`panic-attacker` fills a different niche: **systematic stress testing combined with logic-based bug detection**.

## Core Concepts

### 1. Assail Pre-Analysis

Before attacking a program, we need to understand its structure:

**Goal**: Identify weak points and recommend optimal attack strategies.

**Approach**:
- Parse source code for patterns (unsafe blocks, allocations, I/O)
- Detect frameworks and application type
- Catalog potential vulnerabilities
- Generate attack recommendations

**Output**: A weighted list of attack axes to prioritize.

### 2. Multi-Axis Attack Model

Traditional stress testing focuses on single dimensions. We attack across **six independent axes**:

| Axis | Goal | Examples |
|------|------|----------|
| **CPU** | Exhaust computational resources | Infinite loops, expensive operations |
| **Memory** | Trigger OOM or allocation failures | Large buffers, memory leaks |
| **Disk** | Saturate I/O bandwidth | Massive file operations |
| **Network** | Flood connections | Connection storms, large payloads |
| **Concurrency** | Expose race conditions | Thread/task explosions |
| **Time** | Find time-dependent bugs | Extended runtime, timeouts |

**Key insight**: Many bugs only appear under specific resource pressure.

### 3. Logic-Based Signature Detection

Inspired by **Mozart/Oz** constraint logic programming and **Datalog** inference.

#### Why Logic Programming?

Traditional bug detection uses pattern matching (regex, AST). Logic programming offers:

1. **Declarative Rules**: Express "what to find" not "how to find it"
2. **Inference**: Derive complex patterns from simple facts
3. **Temporal Logic**: Reason about ordering and causality
4. **Constraint Solving**: Handle complex inter-dependencies

#### Datalog Model

We model program behavior as facts and detect bugs via logical inference:

**Facts** (observations):
```
Alloc(heap_var, location=42)
Free(heap_var, location=100)
Use(heap_var, location=150)
```

**Rule** (bug pattern):
```
UseAfterFree(var, use_loc, free_loc) :-
    Free(var, free_loc),
    Use(var, use_loc),
    Ordering(free_loc, use_loc)
```

**Inference**: If we observe `Free(heap_var, 100)` and `Use(heap_var, 150)`, we infer `UseAfterFree(heap_var, 150, 100)`.

#### Implemented Rules

1. **Use-After-Free**
   ```
   UseAfterFree(X, use_loc, free_loc) :-
       Free(X, free_loc),
       Use(X, use_loc),
       free_loc < use_loc
   ```

2. **Double-Free**
   ```
   DoubleFree(X, loc1, loc2) :-
       Free(X, loc1),
       Free(X, loc2),
       loc1 != loc2
   ```

3. **Deadlock** (simplified)
   ```
   Deadlock(M1, M2) :-
       Lock(M1, loc1), Lock(M2, loc2),  # Thread 1 order
       Lock(M2, loc3), Lock(M1, loc4),  # Thread 2 order (reversed)
       Ordering(loc1, loc2),
       Ordering(loc3, loc4)
   ```

4. **Data Race**
   ```
   DataRace(X, loc1, loc2) :-
       Write(X, loc1),
       Read(X, loc2),
       Concurrent(loc1, loc2),
       ¬Synchronized(loc1, loc2)
   ```

### 4. Pattern Libraries

Different program types have different vulnerabilities:

**Web Servers**:
- HTTP flood attacks
- Large POST body handling
- Connection exhaustion

**Databases**:
- Query storms
- Transaction conflicts
- Index corruption

**File Systems**:
- Concurrent file access
- Disk space exhaustion
- Permission errors

**Concurrent Programs**:
- Deadlock induction
- Race condition triggering
- Resource starvation

The Assail analysis selects appropriate patterns based on detected frameworks.

## Architecture

### Data Flow

```
┌─────────────┐
│   Target    │
│   Program   │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Assail Analysis │  ← Static code inspection
│  (assail/*)       │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Attack Planning │  ← Select axes and patterns
│  (patterns.rs)  │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Attack Executor │  ← Execute stress tests
│  (attack/*)     │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Crash Reports   │  ← Collect failures
│  (CrashReport)  │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Signature       │  ← Logic-based inference
│ Detection       │
│ (signatures/*)  │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Report          │  ← Comprehensive report
│ Generation      │
│  (report/*)     │
└─────────────────┘
```

### Module Breakdown

#### `types.rs`
Core type definitions shared across modules.

Key types:
- `Language`, `Framework`: Program classification
- `AttackAxis`, `IntensityLevel`: Attack configuration
- `WeakPoint`, `BugSignature`: Analysis results
- `Fact`, `Predicate`, `Rule`: Logic programming primitives

#### `assail/`
Static analysis and pattern detection.

- `analyzer.rs`: Core analysis engine
  - Language detection
  - Framework identification
  - Weak point extraction
  - Statistics collection

- `patterns.rs`: Pattern library
  - Language-specific patterns
  - Framework-specific patterns
  - Attack recommendations

#### `attack/`
Attack orchestration and execution.

- `executor.rs`: Attack execution engine
  - Strategy selection
  - Process management
  - Crash collection
  - Resource monitoring

- `strategies.rs`: Attack strategy definitions
  - CPU stress algorithms
  - Memory exhaustion techniques
  - I/O saturation methods
  - Concurrency storm patterns

#### `signatures/`
Logic-based bug detection.

- `engine.rs`: Signature detection engine
  - Fact extraction from crashes
  - Rule application
  - Inference execution
  - Confidence scoring

- `rules.rs`: Datalog-style rule definitions
  - Use-after-free rules
  - Deadlock rules
  - Race condition rules
  - Memory corruption rules

#### `report/`
Report generation and formatting.

- `generator.rs`: Report assembly
  - Robustness scoring
  - Issue prioritization
  - Recommendation generation

- `formatter.rs`: Output formatting
  - Console output with colors
  - JSON serialization
  - Pretty printing

## Mozart/Oz Connection

### Why Mozart/Oz?

Mozart/Oz pioneered **constraint logic programming** with:

1. **Unification**: Pattern matching with logical variables
2. **Constraints**: Declarative specification of relationships
3. **Search**: Automatic exploration of solution spaces
4. **Concurrency**: First-class concurrent constraints

### Mapping to panic-attacker

| Mozart/Oz Concept | panic-attacker Implementation |
|-------------------|-------------------------------|
| **Variables** | Program variables and locations |
| **Constraints** | Temporal ordering, type constraints |
| **Unification** | Fact matching in rule bodies |
| **Search** | Inference over fact database |
| **Propagation** | Forward-chaining inference |

### Example: Use-After-Free Detection

**Mozart/Oz style** (pseudocode):
```oz
proc {DetectUAF Facts ?Bugs}
   for Free in Facts.frees do
      for Use in Facts.uses do
         if Free.var == Use.var andthen Free.loc < Use.loc then
            Bugs := UseAfterFree(Free.var, Use.loc, Free.loc) | Bugs
         end
      end
   end
end
```

**panic-attacker style** (Rust):
```rust
fn infer_use_after_free(&self, facts: &HashSet<Fact>) -> Vec<BugSignature> {
    let mut signatures = Vec::new();

    for fact1 in facts {
        if let Fact::Free { var: var1, location: free_loc } = fact1 {
            for fact2 in facts {
                if let Fact::Use { var: var2, location: use_loc } = fact2 {
                    if var1 == var2 && free_loc < use_loc {
                        signatures.push(BugSignature {
                            signature_type: SignatureType::UseAfterFree,
                            // ...
                        });
                    }
                }
            }
        }
    }

    signatures
}
```

Both express the same logical rule: "A use-after-free occurs when a variable is freed before it is used."

## Advanced Features (Future)

### 1. Multi-Program Correlation

Test multiple programs simultaneously to detect:
- Shared resource conflicts
- Protocol violations
- Distributed race conditions

### 2. Corpus-Based Testing

Use real-world data as attack vectors:
- HTTP request logs for web servers
- Query logs for databases
- File system snapshots for FS tools

### 3. Mutation-Based Fuzzing

Combine with traditional fuzzing:
- Generate inputs based on weak points
- Mutate known-good inputs
- Coverage-guided exploration

### 4. Symbolic Execution Integration

Enhance fact extraction with symbolic execution:
- Path constraints as logical facts
- SMT solver for constraint satisfaction
- Precise temporal ordering

### 5. Distributed Attack Orchestration

Scale to large programs:
- Parallel attack execution
- Distributed fact collection
- Centralized inference

## Performance Considerations

### Fact Database Size

For large programs, the fact database can grow exponentially. Mitigations:

1. **Incremental Analysis**: Process crashes as they occur
2. **Fact Pruning**: Discard irrelevant facts early
3. **Index Structures**: Use hash maps for O(1) lookups
4. **Lazy Evaluation**: Defer inference until needed

### Rule Complexity

Some rules (like deadlock detection) require quadratic or higher complexity. Optimizations:

1. **Rule Ordering**: Apply cheap rules first
2. **Short-Circuit Evaluation**: Stop on high-confidence matches
3. **Caching**: Memoize intermediate results
4. **Sampling**: Sample fact space for approximate results

## Comparison to Existing Tools

| Tool | Focus | Approach | Coverage |
|------|-------|----------|----------|
| **AFL** | Fuzzing | Mutation-based | Input space |
| **libFuzzer** | Fuzzing | Coverage-guided | Input + code paths |
| **AddressSanitizer** | Memory bugs | Runtime instrumentation | Execution |
| **ThreadSanitizer** | Concurrency bugs | Happens-before analysis | Thread interactions |
| **Valgrind** | Memory errors | Binary instrumentation | All allocations |
| **panic-attacker** | **Robustness** | **Multi-axis stress + logic** | **Resource pressure + patterns** |

**Key differentiator**: We test under resource pressure, not just correctness.

## Philosophical Foundation

### Robustness vs. Correctness

- **Correctness**: "Does it work?"
- **Robustness**: "Does it work under adversarial conditions?"

Many programs are correct under normal conditions but fail catastrophically under stress. panic-attacker targets this gap.

### Resource-Aware Testing

Traditional testing assumes infinite resources. Real systems have:
- Finite memory
- Limited CPU
- Bounded I/O bandwidth
- Contended locks

panic-attacker respects these limits and exploits them.

### Logic as Specification

Bug patterns are **specifications** of incorrect behavior. Logic programming lets us:

1. **Declare** what's wrong
2. **Infer** when it happens
3. **Prove** it occurred

This is more principled than ad-hoc pattern matching.

## Extended Design Vision (2026-02-07)

The following concepts emerged from design exploration and represent the
longer-term trajectory of panic-attacker.

### Constraint Sets (Composable Stress Profiles)

Real failures are never one thing. They're the intersection of multiple
pressures. A "constraint set" combines conditions that must hold simultaneously:

```yaml
name: "Hot Processor + Falling Memory"
constraints:
  cpu:
    load: 95%
    sustained: true
  memory:
    available: declining
    rate: "100MB/s loss"
    floor: "256MB"
  program:
    must_survive: true
    max_response_time: "500ms"
```

This concept comes directly from Mozart/Oz's constraint stores: accumulate
constraints and let the solver reason about whether they can all be satisfied.

**GUI Vision**: A visual interface where you drag sliders to compose sets:

```
┌──────────────────────────────────────────┐
│  [CPU]     ████████████░░░░  80%         │
│  [Memory]  ██████████████░░  90% ↓ fall  │
│  [Disk]    ████░░░░░░░░░░░░  30%         │
│  [Network] ████████░░░░░░░░  50ms lat    │
│  [Threads] ████████████████  100 threads  │
│  [▶ Run Test]  [💾 Save Profile]          │
└──────────────────────────────────────────┘
```

### Software Fuses

A software fuse is a program component designed to fail safely, protecting the
rest of the system from cascading failure, like an electrical fuse.

**Existing partial solutions**:
- Circuit breakers (Netflix Hystrix) -- service-level only
- OOM killers (earlyoom, systemd-oomd) -- reactive, not proactive
- Watchdog timers -- binary: reset or don't
- Rate limiters -- don't model system topology
- Backpressure (Reactive Streams) -- single pipeline only

**What doesn't exist yet**: A way to DESIGN fuse placement based on resource
flow modelling. panic-attacker reveals where fuses are needed by finding where
things actually break.

```
                    ┌─── CPU FUSE ───┐
                    │ If > 90% for   │
                    │ 30s, shed load  │
                    └────────────────┘
                           │
┌──────────┐    ┌──────────▼───────────┐    ┌──────────┐
│  Input   │───▶│   Core Application   │───▶│  Output  │
│  Queue   │    └──────────┬───────────┘    │  Queue   │
└──────────┘               │                └──────────┘
                    ┌──────▼─────────┐
                    │ MEMORY FUSE    │
                    │ If < 256MB     │
                    │ free, GC + shed│
                    └────────────────┘
                           │
                    ┌──────▼─────────┐
                    │ CASCADE FUSE   │
                    │ If 2+ fuses    │
                    │ tripped, halt  │
                    └────────────────┘
```

panic-attacker's role:
1. **Where fuses are needed** (which resources exhaust first)
2. **What thresholds to set** (at what level does degradation begin)
3. **Whether fuses work** (does the system actually degrade gracefully)
4. **What happens when fuses cascade** (does tripping one cause others)

### The Cisco Analogy: Resource Topology Simulator

Cisco Packet Tracer lets you design network topologies. We model resource flows:

| Network Concept | Resource Equivalent |
|----------------|---------------------|
| Routers | Programs/services |
| Switches | Message queues/buses |
| Cables | API calls / IPC |
| Bandwidth | CPU/memory/disk budgets |
| Latency | Response times |
| Packet loss | Error rates |

This could model both **space** (how resources distribute across services) and
**time** (how resource usage changes over hours/days/growth trajectories).

### Priority Scheduling

"I always need 4 of these running for safety, and that needs to get priority":

```yaml
critical_services:
  - name: "database"
    priority: 1  # Never shed
    min_resources: { cpu: 2, memory: 4GB }
  - name: "api-server"
    priority: 1
    min_resources: { cpu: 1, memory: 2GB }
  - name: "monitoring"
    priority: 2  # Shed under pressure
  - name: "cache"
    priority: 3  # Shed first

resource_policy:
  shed_order: [3, 2]
  never_shed: [1]
```

panic-attacker tests these policies by simulating pressure and verifying
shedding happens correctly.

### eclexia Integration

eclexia's resource-tracking creates a natural integration:
1. eclexia programs declare resource expectations
2. panic-attacker verifies those declarations under stress
3. eclexia programs can BE software fuses (adaptive resource response)
4. panic-attacker profiles eclexia as a demonstration of its value

### ML Extensions

Every panic-attacker run generates labelled training data:
- Input: program type, language, frameworks, attack axes, intensity
- Output: crash/survive, signatures detected, resource curves

Over time, this enables:
- Bug classification by similarity to known patterns
- Attack strategy optimisation (learn what's most effective)
- Threshold prediction (predict failure point without reaching it)
- Anomaly detection (flag unusual behaviour during tests)

## Product Boundaries

### Definitely panic-attacker (this repo)
- Assail static analysis
- Multi-axis attack execution
- Signature detection (Datalog-style)
- Pattern library
- Constraint sets / stress profiles
- Program-data corruption testing
- Multi-program interaction testing

### Probably Separate Products
- **Resource Topology Simulator** -- GUI, Cisco-like
- **Software Fuse Framework** -- Rust library
- **eclexia Profiler** -- eclexia-specific integration
- **Safety Priority Scheduler** -- Production daemon

## Roadmap

### v0.1 (Current) -- Foundation
- [x] CLI with assail, attack, assault, analyze commands
- [x] Assail static analysis
- [x] 6 attack axes
- [x] Pattern-based signature detection
- [x] Report generation with scoring

### v0.2 -- Constraint Sets
- [ ] YAML-based stress profile definitions
- [ ] Composable multi-axis conditions
- [ ] Program-data corruption testing
- [ ] Multi-program interaction testing

### v0.3 -- Intelligence
- [ ] Datalog engine integration (Crepe or Datafrog)
- [ ] ML-based signature classification
- [ ] Anomaly detection
- [ ] Threshold prediction

### v0.4 -- Ecosystem
- [ ] eclexia integration
- [ ] Software Fuse Framework
- [ ] CI/CD pipeline integration
- [ ] Resource Topology Simulator (separate project)

### v1.0 -- Production
- [ ] Priority-aware resource scheduling
- [ ] Topology designer GUI
- [ ] Trained ML models
- [ ] Enterprise reporting

## References

- **Mozart/Oz**: Van Roy, P., & Haridi, S. (2004). *Concepts, Techniques, and Models of Computer Programming*
- **Datalog**: Abiteboul, S., Hull, R., & Vianu, V. (1995). *Foundations of Databases*
- **Stress Testing**: Basili, V. R., & Selby, R. W. (1987). *Comparing the Effectiveness of Software Testing Strategies*
- **Sanitizers**: Serebryany, K., et al. (2012). *AddressSanitizer: A Fast Address Sanity Checker*
- **Chaos Engineering**: Rosenthal, C., et al. (2017). *Chaos Engineering*
- **Circuit Breakers**: Nygard, M. (2007). *Release It!*

## License

SPDX-License-Identifier: PMPL-1.0-or-later
