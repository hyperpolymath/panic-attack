# SPDX-License-Identifier: PMPL-1.0-or-later

# panic-attack: Extended Vision

> **Note**: This document captures long-range design thinking from 2026-02-07. The near-term
> items have been implemented. See `ROADMAP.md` for current priorities.

## Raw Design Thinking (2026-02-07)

This document captures the full stream-of-consciousness design exploration
that led to panic-attacker. These are ideas at various stages of maturity --
some immediately actionable, some long-term visions, some may turn out to be
separate products entirely. They're preserved here as a seedbed for future
development.

---

## The Origin Story

On 2026-02-07, a system running Fedora Kinoite crashed. Investigation revealed:

1. **24 MCP servers** consuming 300%+ CPU simultaneously
2. **19 eclexia interpreter crashes** (actually valid conformance tests running
   stack overflow tests) were mistaken for system crashes
3. **KWin Wayland compositor** hung under CPU pressure, freezing the system
4. **No existing tool** could have predicted or prevented this

The question was: "What if we had a program that could stress-test any
program and tell us exactly how it will fail, and identify the signature
of the underlying issue -- not just that it crashed, but what class of
problem caused it?"

---

## Core Ideas (Expanded)

### 1. The Assail (Pre-Attack Analysis)

You can learn a lot about a program's vulnerabilities without running it.
Just knowing what language it's written in tells you what classes of bugs
to look for:

- **Rust**: unsafe blocks, unwrap panics, Arc<Mutex<T>> deadlocks
- **C/C++**: malloc/free pairs, buffer operations, pointer arithmetic
- **Julia**: type instability, GC pressure, ccall FFI issues
- **Gleam/Elixir**: Process mailbox overflow, GenServer bottlenecks
- **Any program**: Recursion depth, file I/O, network calls, concurrency

The Assail builds a **vulnerability profile** before any attack begins,
allowing targeted testing instead of blind brute force.

### 2. Attack Axes (Controllable Dimensions)

Real failures happen along specific resource dimensions. Being able to
control each independently AND in combination is critical:

- **CPU** -- "What happens when the processor is saturated?"
- **Memory** -- "What happens when heap pressure increases?"
- **Disk** -- "What happens when I/O is slow or disk is full?"
- **Network** -- "What happens when connections are slow/failing?"
- **Concurrency** -- "What happens with thread contention?"
- **Time** -- "What happens when operations timeout?"

**Key insight:** You need to test these individually AND compose them
into sets.

### 3. Constraint Sets ("The Sets Thing")

**This is the most powerful idea.** Real failures are never one thing.
They're the intersection of multiple pressures.

"Hot processor AND falling memory" is fundamentally different from testing
each alone.

A constraint set is a named combination of conditions:

```yaml
"Production Spike":
  cpu: 80% + periodic 100% spikes
  memory: 70% with 2% leak rate
  network: 50ms latency + 1% loss
  disk: 85% full
```

**Future GUI:** Drag sliders to compose sets visually, then watch
your program struggle in real-time. You say "I want to see it sitting
on a hot processor with free memory dropping" and simply drag those
sliders into position.

**Deeper insight:** Sets could be used for design:
- "I always need 4 of these things running for safety"
- "That needs to get priority on X or Y"
- "Beyond that, more memory for these, more processor for those"

This becomes a tool for designing resource allocation policies,
not just testing them.

### 4. The Mozart/Oz Connection (Logic-Based Detection)

Mozart/Oz pioneered constraint logic programming. We use three ideas:

1. **Constraint stores** -- Accumulate evidence during testing, like Oz
   accumulates constraints in a store
2. **Logic programming** -- Derive conclusions about bug classes from
   evidence, using Datalog rules
3. **Concurrent reasoning** -- Analyse crash evidence while attacks are
   still running

The signature engine doesn't just say "it crashed with SIGSEGV". It says
"this is a use-after-free with 95% confidence, and here's the logical
proof."

### 5. Software Fuses

A **software fuse** is a program component designed to fail safely,
protecting the rest of the system from cascading failure.

**Existing concepts and their limitations:**

| Concept | What It Does | Limitation |
|---------|-------------|------------|
| Circuit breakers (Hystrix) | Cut off failing services | Service-level only |
| OOM killers (earlyoom) | Kill processes before OOM | Reactive, not proactive |
| Watchdog timers | Reset if system hangs | Binary: reset or don't |
| Rate limiters | Prevent overload | Don't model topology |
| Backpressure | Slow producers | Single pipeline only |

**What doesn't exist yet:** A way to DESIGN fuse placement based on
resource flow modelling. Nobody has built a system for designing safety
topologies -- placing fuses deliberately based on how resources actually
flow through a system.

panic-attacker reveals where fuses are needed by finding where things
actually break. Then you can build programs that operate as fuses
themselves, cutting out before other parts of the system are damaged --
like a surge protector for software.

**Connection to eclexia:** eclexia's resource-tracking makes programs
that are inherently fuse-aware. An eclexia program monitors its own
resource consumption as a first-class language feature and can respond
adaptively. panic-attacker proves whether that response actually works.

### 6. The Cisco Analogy (Resource Topology Simulator)

Cisco Packet Tracer lets you design network topologies, simulate traffic,
and test failure scenarios. panic-attacker could evolve into the same
thing for **resource topologies**:

```
Instead of:     We model:
Routers         Programs/services
Switches        Message queues/buses
Cables          API calls / IPC
Bandwidth       CPU/memory/disk budgets
Latency         Response times
Packet loss     Error rates
```

**Design in space and time:**
- **Space** -- How resources distribute across services/machines
- **Time** -- How resource usage changes (daily patterns, growth)

This means designing safety margins that account for peak usage, growth
trajectories, seasonal variations, and cascading failure sequences.

It could help you design networks of things -- not just testing individual
programs, but understanding the energetics of optimisation and safety
across a designed system, whether that design is spatial (architecture)
or temporal (process/workflow).

### 7. Priority Scheduling

"I always need 4 of these running for safety":

```yaml
priority_1_never_shed:
  - database
  - api-server
  - monitoring-core
  - auth-service

priority_2_shed_under_pressure:
  - logging
  - analytics

priority_3_shed_first:
  - cache
  - preview-generator
```

panic-attacker tests whether shedding works:
1. Simulate resource pressure
2. Verify priority 3 sheds first
3. Verify priority 1 maintains performance
4. Verify recovery when pressure subsides

### 8. ML and Pattern Recognition

Every panic-attacker run generates labelled training data. Over time:

1. **Bug classification** -- "This crash is 87% similar to known
   use-after-free patterns"
2. **Attack optimisation** -- "For Rust web servers, memory attacks
   find bugs 3x faster"
3. **Threshold prediction** -- "This program will OOM at ~847MB"
4. **Anomaly detection** -- "This behaviour is unusual for this type"

---

## Product Boundaries: One Tool or Many?

### Definitely panic-attacker (this repo)
- Assail static analysis
- Multi-axis attack execution
- Signature detection (Datalog-style)
- Pattern library
- Constraint sets / stress profiles
- Program-data corruption testing
- Multi-program interaction testing
- ML-enhanced detection (as plugin)

### Probably Separate Products
- **Resource Topology Simulator** -- GUI application (Cisco-like visual tool)
- **Software Fuse Framework** -- Rust library for building fuse components
- **eclexia Profiler** -- eclexia-specific stress testing integration
- **Safety Priority Scheduler** -- Production daemon for resource management

### Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                panic-attacker (core)                     │
│  Assail │ Attack │ Signatures │ Profiles │ Reports       │
└────┬────────┬────────┬────────────┬──────────┬──────────┘
     │        │        │            │          │
     ▼        │        ▼            │          ▼
┌─────────┐   │  ┌──────────┐      │   ┌────────────┐
│eclexia  │   │  │ Fuse     │      │   │ Resource   │
│profiler │   │  │ Framework│      │   │ Topology   │
│(plugin) │   │  │(library) │      │   │ Simulator  │
└─────────┘   │  └──────────┘      │   │ (GUI app)  │
              │                    │   └────────────┘
              ▼                    ▼
       ┌────────────┐     ┌──────────────┐
       │ CI/CD      │     │ Safety       │
       │ Integration│     │ Scheduler    │
       │ (plugin)   │     │ (daemon)     │
       └────────────┘     └──────────────┘
```

---

## The Name

"panic-attacker" was chosen because:
1. It attacks programs to make them panic
2. It identifies panic-worthy issues before production
3. It's easy to spell (unlike "claustrophobia")
4. The Rust community already understands "panic"

Alternative considered: **claustrophobia** -- because the program would
be highly constrained during testing. Excellent concept, terrible spelling.
But the constraint idea lives on in the "constraint sets" feature.

---

## Long-Range: Soft Systems + Set Theory + Sensor/Actuator Integration

### The Physical World Connection

If we integrate panic-attacker's constraint sets with **soft systems
methodology** (Checkland) and **set theory**, we arrive at something
genuinely novel: modelling real-world sensor/actuator systems using the
same constraint-based stress testing framework.

Consider: a sensor/actuator setup is fundamentally a system where:
- **Sensors** collect facts (like our trace collector)
- **Controllers** apply rules (like our Datalog engine)
- **Actuators** take action (like our fuse/circuit breaker response)

The constraint set concept maps directly:

```
Software World              Physical World
─────────────               ──────────────
CPU load sensor    ↔    Temperature sensor
Memory monitor     ↔    Pressure sensor
Error rate metric  ↔    Vibration sensor
Fuse/breaker       ↔    Safety valve
Load shedding      ↔    Power cutoff
Graceful degrade   ↔    Controlled shutdown
```

### Set-Theoretic Modelling

Using set theory to define safety boundaries:

```
Let S = {s₁, s₂, ..., sₙ} be the set of all system states
Let SAFE ⊂ S be the set of safe states
Let CRITICAL ⊂ S be the set of critical states
Let FUSE_i: S → S be the fuse function for resource i

Invariant: ∀s ∈ CRITICAL, ∃i : FUSE_i(s) ∈ SAFE

"For every critical state, there exists a fuse that returns
the system to a safe state."
```

panic-attacker tests whether this invariant actually holds.

### Soft Systems Methodology (SSM)

Peter Checkland's SSM provides a framework for analysing "messy" real-world
situations. Applied to panic-attacker:

- **Root definitions** -- What is the system trying to do?
- **CATWOE analysis** -- Customers, Actors, Transformation, Weltanschauung,
  Owner, Environment
- **Conceptual models** -- Ideal system behaviour under stress
- **Comparison** -- Compare ideal with actual (panic-attacker results)

This is NOT immediate work. But it places panic-attacker in a trajectory
toward being useful for:

1. **Industrial control systems** -- Test PLCs and SCADA-like setups
2. **IoT networks** -- Test sensor mesh behaviour under stress
3. **Robotics** -- Test actuator response under degraded conditions
4. **Smart buildings** -- Test HVAC/power/security system interactions
5. **Vehicle systems** -- Test ECU network behaviour under failures

### Roadmap Position

This is long-range (v2.0+). The path:

```
v0.1: Software stress testing (now)
v0.2: Constraint sets (composable conditions)
v0.3: ML-enhanced detection
v0.4: Resource topology simulator
v1.0: Production-grade software testing
────── bridge ──────
v1.5: Generic constraint modelling (not software-specific)
v2.0: Sensor/actuator integration
v2.5: Physical system modelling
v3.0: Digital twin stress testing
```

The key insight: if the constraint engine is general enough, the leap
from "test software under stress" to "test any system under stress"
is not as large as it seems.

### eclexia Fuses: A Deeper Concept

The existing "software fuse" concepts (circuit breakers, OOM killers,
backpressure) all operate at a single abstraction layer. They're
application-level patches, not first-class engineering constructs.

eclexia changes this fundamentally. Because eclexia has **first-class
resource constraint control** built into the language itself, fuses
designed in eclexia can operate **right through abstraction layers** --
from application logic down to memory allocation, from network I/O up
to business rules.

This means eclexia fuses aren't limited to "if memory > 90%, shed load".
They can express constraints with the same precision as engineering
equations, regardless of dimensionality:

```
# An eclexia fuse isn't a simple threshold.
# It's a constraint over arbitrary dimensions,
# just as an engineer would design a physical safety system.

@resource_constraint
fn thermal_protection(system: System) -> Action {
    # Model heat dissipation as if it were a physical equation
    let heat_gen = system.cpu_watts + system.io_watts
    let heat_dissip = system.cooling_capacity
    let thermal_mass = system.memory_footprint * SPECIFIC_HEAT

    # dT/dt = (heat_gen - heat_dissip) / thermal_mass
    let temp_rate = (heat_gen - heat_dissip) / thermal_mass

    # Fuse triggers based on TRAJECTORY, not just threshold
    if temp_rate > 0 && projected_temp(system, 30.seconds) > MAX_TEMP {
        Action::ShedLoad(proportional_to: temp_rate)
    } else {
        Action::Continue
    }
}
```

The key difference from existing circuit breakers:

| Traditional Fuse | eclexia Fuse |
|-----------------|--------------|
| Single threshold | Multi-dimensional constraint |
| Binary (trip/don't) | Proportional response |
| Application layer only | All abstraction layers |
| Hardcoded parameters | Engineered equations |
| Reactive (already failed) | Predictive (trajectory-based) |
| One resource dimension | Arbitrary dimensionality |

This is genuinely novel: treating software resource management with
the same rigour as physical/chemical engineering. You design fuses the
way you'd design pressure relief valves or thermal cutoffs -- with
equations, not if-statements.

panic-attacker's role becomes testing whether these engineered fuses
actually work under real stress, just as you'd test a physical safety
valve under real pressure.

### Abstractly Mathematical Fusing

Taking this further: there is **no fundamental difference** between a
software resource fuse and a physical safety system when your language
treats resource constraints as first-class mathematical objects.

An eclexia fuse can be:

- A **differential equation**: dS/dt = f(inputs) - g(dissipation)
- A **set-theoretic invariant**: system_state ∈ SAFE_SET
- A **topological constraint**: trajectory stays within safe manifold
- A **chemical equation**: reaction_rate < critical_threshold
- A **purely abstract relationship**: any mathematical predicate

```
# This is simultaneously valid as:
# - Software resource management
# - Thermal engineering model
# - Chemical process safety
# - Abstract mathematical constraint

@fuse(dimensions: arbitrary)
fn universal_safety_constraint<D: Dimension>(
    state: State<D>,
    rate: Rate<D>,
    safe_set: Set<D>,
) -> FuseAction {
    let trajectory = integrate(state, rate, dt: 30.seconds)
    if !safe_set.contains(trajectory.endpoint) {
        FuseAction::Trip(
            magnitude: safe_set.distance(trajectory.endpoint),
            urgency: rate.magnitude(),
        )
    } else {
        FuseAction::Monitor
    }
}
```

The same eclexia program could model:
- A CPU thermal envelope (software)
- An actual thermal envelope (physical)
- A pressure vessel safety margin (chemical engineering)
- A portfolio risk boundary (financial)
- An abstract mathematical constraint surface (pure maths)

**The maths is identical.** The dimensionality and physical interpretation
change, but the constraint logic, the fuse behaviour, and the testing
methodology remain the same.

This makes panic-attacker the **universal test rig** for any constraint-
based safety system, regardless of whether it protects software resources,
models physical systems, or operates in purely abstract mathematical
spaces. eclexia provides the language to express these constraints with
engineering precision, and panic-attacker proves they hold under stress.

---

## Open Questions

1. Should constraint sets use YAML, a custom DSL, or eclexia itself?
2. Should the Resource Topology Simulator be a separate product or mode?
3. How deeply should eclexia integration go -- plugin or first-class?
4. Should the Fuse Framework be Rust-only or language-agnostic?
5. Is there a market for "Safety-as-a-Service" built on these ideas?
6. Can we use eBPF for zero-overhead trace collection?
7. Should the GUI be Tauri (Rust+web) or Dioxus (pure Rust)?
8. How early should we design for physical system modelling?
9. Could eclexia's economics-as-code literally model resource economics
   of physical systems?
10. Is there an existing standard for sensor/actuator constraint
    modelling we should be compatible with? (OPC-UA? MQTT?)

---

## Next Steps

1. Get v0.1 compiling and tested on real programs
2. Test on eclexia (the stack overflow conformance tests are ideal)
3. Add constraint set YAML support (v0.2)
4. Prototype GUI slider interface
5. Explore Datalog engine integration (Crepe or Datafrog)
6. Document fuse patterns from real-world testing
7. Design the Resource Topology Simulator architecture

---

*This is a living document. Ideas will be refined, merged, split, and
sometimes discarded as the project evolves.*

## Authors

- **Concept & Design:** Jonathan D.A. Jewell
- **Initial Implementation:** Claude (Anthropic) + Jonathan D.A. Jewell
- **Date:** 2026-02-07
