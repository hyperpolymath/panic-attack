<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

# Patch Bridge — Design Document

**Status**: Draft v0.1.0
**Author**: Jonathan D.A. Jewell
**Date**: 2026-03-21
**Position**: Subcommand family within `panic-attack`, with PanLL panel and BoJ cartridge

---

## 1. Problem Statement

When a CVE is disclosed against an upstream dependency, developers face a gap between
disclosure and fix. Current tooling (Trivy, Grype, Snyk, OSV-Scanner, `cargo audit`)
detects the CVE but offers no systematic mitigation, no lifecycle management, and no
contextual risk assessment. Developers are left to:

1. Manually search for workarounds
2. Assess severity using generic CVSS scores that ignore their specific code paths
3. Apply ad-hoc fixes with no proof of correctness
4. Forget to remove mitigations when upstream patches land
5. Miss concatenative risks where low-severity CVEs combine to create critical exposure

**Patch Bridge** closes this gap by providing:

- **Multi-source CVE intelligence** with bubble detection (the "Ground News" model)
- **Contextual risk assessment** using the existing miniKanren taint/crosslang engines
- **Formally verified mitigations** via Idris2 dependent types
- **Unmitigability proofs** — machine-checked evidence that no layered control suffices
- **Concatenative danger detection** — identifying CVE combinations that multiply risk
- **Lifecycle management** — apply, monitor, auto-retire when upstream fixes land
- **Developer interview mode** — guided flow-charting to build accurate data-flow models
- **Adoption gate** — risk assessment *before* adding a dependency
- **Upstream feedback** — contributing proven mitigations back to maintainers
- **Cross-domain translation** — explaining threats in the developer's own conceptual framework

---

## 2. Architecture Overview

```
                ┌──────────────────────────────────────┐
                │           CVE INTELLIGENCE           │
                │         (Multi-Source Feeds)          │
                │                                      │
                │  Tier 1: NVD, GHSA, OSV, vendor      │
                │  Tier 2: VirusTotal, ExploitDB,      │
                │          language-specific advisories │
                │  Tier 3: oss-security, academic,     │
                │          upstream commit analysis,    │
                │          international forums         │
                │                                      │
                │  → Bubble rating per CVE              │
                │  → Source divergence alerts           │
                └──────────────┬───────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │          ADOPTION GATE               │
                │     "Should we use this dep?"        │
                │                                      │
                │  - CVE history patterns              │
                │  - Maintainer response time stats    │
                │  - Vulnerability class recurrence    │
                │  - Which code paths YOU will touch   │
                │  - Alternative comparison matrix     │
                │  - proven/ verified replacements      │
                └──────────────┬───────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │         FLOW ANALYSIS                │
                │    "Where does data touch vulns?"    │
                │                                      │
                │  - Call graph extraction (existing    │
                │    kanren taint engine)               │
                │  - Trust boundary mapping (existing   │
                │    kanren crosslang engine)           │
                │  - Developer interview mode (new)     │
                │  - Flow chart artifact persistence    │
                │  - Automatic reanalysis on new CVEs   │
                └──────────────┬───────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
 ┌───────▼──────┐     ┌───────▼──────┐     ┌───────▼───────┐
 │  MITIGABLE   │     │ UNMITIGABLE  │     │ CONCATENATIVE │
 │              │     │              │     │               │
 │ Generate     │     │ RED ALERT    │     │ CVE×CVE       │
 │ mitigation   │     │              │     │ interaction   │
 │ w/ Idris2    │     │ Prove no     │     │ across shared │
 │ soundness    │     │ mitigation   │     │ trust         │
 │ proof        │     │ exists       │     │ boundaries    │
 │              │     │              │     │               │
 │ Apply →      │     │ Rearchitect  │     │ Multiplicat-  │
 │ Monitor →    │     │ guidance +   │     │ ive risk      │
 │ Auto-retire  │     │ proven/      │     │ scoring       │
 │              │     │ alternatives │     │               │
 └──────────────┘     └──────────────┘     └───────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │       MITIGATION REGISTRY            │
                │                                      │
                │  - Active mitigations + proofs       │
                │  - Expiry / review dates             │
                │  - Upstream fix watch (GitHub/crate)  │
                │  - Auto-retire on upstream release    │
                │  - Revert verification               │
                │  - VeriSimDB persistence (hexads)    │
                └──────────────┬───────────────────────┘
                               │
                ┌──────────────▼───────────────────────┐
                │       UPSTREAM FEEDBACK              │
                │                                      │
                │  - Export proven mitigation as PR     │
                │  - Attach Idris2 soundness proof     │
                │  - Track upstream adoption           │
                └──────────────────────────────────────┘
```

---

## 3. Integration with Existing panic-attack Infrastructure

Patch Bridge is **not** a separate tool. It extends panic-attack's existing
capabilities with new subcommands and new modules that compose with the
miniKanren engine, taint analysis, and cross-language reasoning.

### 3.1 Existing infrastructure reused

| Component | Location | Reuse in Patch Bridge |
|-----------|----------|----------------------|
| miniKanren core | `src/kanren/core.rs` | FactDB for CVE facts, forward chaining for concatenative analysis |
| Taint analysis | `src/kanren/taint.rs` | Source→sink tracking to determine if a CVE is reachable |
| Cross-language | `src/kanren/crosslang.rs` | FFI/NIF boundary analysis for cross-language CVE chains |
| Search strategy | `src/kanren/strategy.rs` | Risk-weighted prioritisation of which CVEs to assess first |
| Signatures | `src/signatures/` | Bug signature patterns to match CVE vulnerability classes |
| Attestation | `src/attestation/` | Cryptographic proof chain for mitigation verification |
| VeriSimDB | `src/storage/` | Hexad persistence for mitigation registry |
| PanLL export | `src/panll/` | Event-chain model for panel visualisation |
| Assemblyline | `src/assemblyline.rs` | Batch CVE assessment across org repos |
| Notify | `src/notify.rs` | Alerts on unmitigable CVEs, upstream fix availability |

### 3.2 New modules

```
src/
├── bridge/                    # Patch Bridge core
│   ├── mod.rs                 # Public API
│   ├── intelligence.rs        # Multi-source CVE feed aggregation
│   ├── bubble.rs              # Source divergence / bubble detection
│   ├── gate.rs                # Adoption gate (pre-dependency assessment)
│   ├── flow.rs                # Developer interview + flow chart persistence
│   ├── classify.rs            # Mitigable / Unmitigable / Concatenative triage
│   ├── mitigate.rs            # Mitigation generation and application
│   ├── registry.rs            # Active mitigation tracking + lifecycle
│   ├── retire.rs              # Upstream watch + auto-retirement
│   ├── concatenate.rs         # CVE×CVE interaction analysis
│   ├── translate.rs           # Cross-domain threat translation
│   └── upstream.rs            # Upstream feedback (PR generation, proof export)
```

### 3.3 New subcommands

```
panic-attack bridge              # Full Patch Bridge assessment
panic-attack bridge intel        # Multi-source CVE intelligence report
panic-attack bridge gate <dep>   # Pre-adoption risk assessment
panic-attack bridge flow         # Developer interview mode
panic-attack bridge triage       # Classify all CVEs (mitigable/unmitigable/concat)
panic-attack bridge mitigate     # Generate + apply mitigations
panic-attack bridge status       # Active mitigation registry
panic-attack bridge retire       # Check for upstream fixes, retire mitigations
panic-attack bridge upstream     # Generate upstream contribution
```

---

## 4. Multi-Source CVE Intelligence

### 4.1 Source tiers

**Tier 1 — Standard advisories** (polled every 6 hours):
- National Vulnerability Database (NVD) via REST API
- GitHub Security Advisories (GHSA) via GraphQL
- Open Source Vulnerabilities (OSV) via API
- Vendor-specific: Microsoft, Red Hat, Canonical

**Tier 2 — Community intelligence** (polled every 2 hours):
- VirusTotal file/hash reports + community comments (API v3)
- ExploitDB / Packet Storm (scrape or mirror)
- Language-ecosystem advisories:
  - RustSec (rustsec-advisory-db)
  - npm advisories (via registry API)
  - Hex advisories (Elixir/Erlang)
  - PyPI/safety-db (legacy, for migration tracking)
  - Go vulndb
- Distro security trackers:
  - Debian Security Tracker
  - Fedora Bodhi
  - Alpine SecDB
  - SUSE/openSUSE

**Tier 3 — Long tail** (polled daily):
- oss-security mailing list archive
- Full Disclosure mailing list
- arXiv cs.CR (security pre-prints)
- USENIX Security / IEEE S&P proceedings
- Upstream commit analysis: scan recent commits in dependency repos for
  security-related keywords (`CVE`, `security`, `vulnerability`, `buffer`,
  `overflow`, `injection`, `traversal`, `bypass`) — the fix often lands
  before the CVE is assigned
- Bug bounty public disclosures (HackerOne, Bugcrowd public reports)
- CWE database (for vulnerability class mapping)

### 4.2 Bubble rating

Each CVE receives a **coverage vector** indicating which source tiers report it:

```
CVE-2026-XXXX
  Tier 1: ████░░  (NVD: yes, GHSA: yes, OSV: no, vendor: no)
  Tier 2: ██████  (VT: yes, ExploitDB: yes, RustSec: yes)
  Tier 3: ██░░░░  (oss-security: yes, academic: no, commits: no)

  Coverage: 6/13 sources
  Bubble risk: MODERATE — you're missing upstream commit analysis
  and vendor advisory. VirusTotal community has 2 exploit PoCs
  not mentioned in NVD description.
```

**Bubble warnings** fire when:
- A CVE appears in Tier 2/3 but NOT Tier 1 (early warning)
- Exploit PoCs exist in community sources but official advisory says "no known exploits"
- Severity ratings diverge significantly between sources
- A vulnerability class has been discussed in academic literature but no CVE exists yet

### 4.3 Cross-domain translation

When reporting a CVE to a developer, Patch Bridge adapts the explanation to their
language ecosystem:

```rust
/// Cross-domain threat translation
///
/// Maps vulnerability classes to concepts familiar in the target language.
/// A C developer understands buffer overflows natively but needs help seeing
/// how linear types would prevent them. An Elixir developer understands
/// process isolation but needs to know it doesn't protect against NIF crashes.
pub struct ThreatTranslator {
    /// The developer's primary language/ecosystem
    target_ecosystem: Ecosystem,
    /// Known conceptual gaps for this ecosystem
    blind_spots: Vec<BlindSpot>,
}
```

**Translation examples:**

| Vuln class | To C developer | To Elixir developer | To ReScript developer |
|------------|---------------|--------------------|-----------------------|
| Buffer overflow | "You know this one — but did you know linear types prevent this class entirely?" | "Your NIF dependency has this. BEAM isolation does NOT help — NIFs run in scheduler threads." | "Your JS FFI calls a native module with this. ReScript's type safety stops at the FFI boundary." |
| Deserialization | "Marshal/pickle equivalent — untrusted data becomes executable." | "`:erlang.binary_to_term` with untrusted input. Use `:safe` option or proven/binary_decoder." | "JSON.parse is safe for data, but your dep deserializes into executable structures." |
| Race condition | "You know mutexes. But your dep uses lock-free structures with a known ABA problem." | "Unusual here, but this dep uses a NIF with mutable global state — breaks your concurrency guarantees." | "Your ReScript is safe, but the JS interop target has shared mutable state in a worker." |

---

## 5. Contextual Risk Assessment

### 5.1 Reachability analysis (existing kanren taint engine)

The existing taint analysis in `src/kanren/taint.rs` already tracks
source→sink flows. Patch Bridge extends this by matching CVE vulnerability
classes to taint sink categories:

```
CVE vulnerability class    →  TaintSink mapping
───────────────────────────────────────────────
Command injection          →  ShellCommand, CodeExecution
SQL injection              →  SqlQuery
Path traversal             →  FilePath
Deserialization attack     →  DeserializeSink
XSS                        →  NetworkWrite
Buffer overflow            →  MemoryOperation, UnsafeCast
Atom exhaustion            →  AtomCreation
```

If no taint flow reaches the CVE's vulnerability class sink, the CVE is
**contextually unreachable** — informational only.

If a taint flow DOES reach it, Patch Bridge reports the exact source→sink
path through the developer's code.

### 5.2 Developer interview mode

Static taint analysis is imperfect. Patch Bridge supplements it with a
guided interview that builds a **flow chart artifact**:

```
$ panic-attack bridge flow

Patch Bridge Flow Interview
============================

Your project uses 47 dependencies. I'll ask about the ones that
handle untrusted input.

[1/5] You depend on `serde_json` (v1.0.128).
      How does untrusted data reach JSON parsing in your app?

      (a) HTTP request bodies
      (b) File uploads
      (c) WebSocket messages
      (d) CLI arguments
      (e) Internal only — data is always trusted
      (f) I'm not sure
      (custom) Describe your flow...

> a, c

      Noted: serde_json receives untrusted data via HTTP and WebSocket.
      This matches CVE-2026-XXXX (stack overflow on deeply nested JSON).
      Risk: HIGH in your context (directly exposed to user input).

[2/5] You depend on `image` (v0.25.1).
      How does untrusted data reach image processing?
      ...
```

The interview produces a **flow chart artifact** stored in
`.machine_readable/patch-bridge/flows.scm`:

```scheme
(flow-chart
  (version "0.1.0")
  (project "my-project")
  (interviewed "2026-03-21")
  (flows
    (flow
      (dependency "serde_json")
      (version "1.0.128")
      (sources (http-request websocket))
      (trust-level untrusted)
      (notes "Direct user input, no pre-validation"))
    (flow
      (dependency "image")
      (version "0.25.1")
      (sources (file-upload))
      (trust-level untrusted)
      (notes "User-uploaded avatars, max 5MB enforced at proxy"))))
```

This artifact persists across sessions. When new CVEs are disclosed, Patch
Bridge re-evaluates against the stored flows without re-interviewing.

### 5.3 PanLL interview panel

In PanLL, the interview mode becomes visual: developers drag-and-drop
data flow connections in the panel, and Patch Bridge overlays CVE exposure
on the resulting graph. See Section 9 for panel design.

---

## 6. Mitigation Classification

### 6.1 Three-way triage

Every CVE affecting a project is classified into exactly one category:

**MITIGABLE** — A layered control can prevent exploitation without
removing the dependency. Examples:
- Input validation before the vulnerable code path
- Sandboxing (seccomp, pledge, WASM isolation)
- Feature disabling (turn off the vulnerable parser option)
- Drop-in replacement from proven/ repository
- Configuration change (disable XXE, limit recursion depth)

**UNMITIGABLE** — No feasible mitigation exists given the project's
constraints. The vulnerability is reachable, exploitable, and no control
can be layered between attacker-controlled input and the vulnerable code.
The only options are: replace the dependency, rearchitect, or accept the risk.

**CONCATENATIVE** — Two or more CVEs that are individually low/medium
severity combine to create a critical risk because they share a trust
boundary, data flow, or privilege escalation path in the project's
specific architecture.

### 6.2 Formal classification (Idris2)

The classification is not heuristic — it is a type-level proof:

```idris
-- src/abi/Bridge/Classify.idr

||| Result of attempting to mitigate a vulnerability in context
data MitigationResult : (vc : VulnClass) -> (ctx : AppContext) -> Type where
  ||| A mitigation exists with a machine-checked soundness proof
  Mitigated : (m : Mitigation vc)
           -> (prf : MitigationSound m vc ctx)
           -> MitigationResult vc ctx

  ||| No mitigation exists — proven impossible given context constraints
  Unmitigable : (prf : NoMitigationExists vc ctx)
             -> MitigationResult vc ctx

  ||| Risk is multiplicative across vulnerability combination
  Concatenated : (vs : Vect (S (S n)) (vc' : VulnClass ** ActiveCVE vc'))
              -> (boundary : SharedBoundary vs ctx)
              -> (prf : MultiplicativeRisk vs boundary)
              -> MitigationResult vc ctx

||| A mitigation is sound iff: for all inputs that would trigger the
||| vulnerability, the mitigation transforms them into inputs that
||| do not trigger the vulnerability, while preserving the required
||| application behaviour.
MitigationSound : Mitigation vc -> VulnClass -> AppContext -> Type
MitigationSound m vc ctx =
  (input : Input ctx)
  -> Triggers input vc
  -> (Not (Triggers (apply m input) vc), PreservesBehaviour (apply m input) ctx)

||| No mitigation exists: for any candidate mitigation, either it fails
||| to prevent the vulnerability or it breaks required behaviour.
NoMitigationExists : VulnClass -> AppContext -> Type
NoMitigationExists vc ctx =
  (m : Mitigation vc) -> Either
    (input ** (Triggers input vc, Triggers (apply m input) vc))
    (input ** Not (PreservesBehaviour (apply m input) ctx))
```

When Patch Bridge says "unmitigable," it carries a proof. This is
fundamentally different from a heuristic severity score.

---

## 7. Concatenative Danger Detection

### 7.1 The problem

Two CVEs scored "Medium" (CVSS 5.0) individually may be catastrophic
together if they share a trust boundary in the project's architecture:

```
CVE-A: Input parsing weakness in libfoo (Medium)
CVE-B: Privilege escalation in libbar (Medium)

In YOUR project:
  User input → libfoo.parse() → libbar.execute()

Combined: User input bypasses foo's weak parsing → triggers bar's
privilege escalation → arbitrary code execution as service user.

Individual CVSS: 5.0 + 5.0
Actual combined risk: 9.8 (Critical)
```

### 7.2 Detection mechanism

Patch Bridge extends the miniKanren FactDB with CVE interaction rules:

```
Rule: concatenative_danger
  IF   cve(A, lib_X, vuln_class_1)
  AND  cve(B, lib_Y, vuln_class_2)
  AND  data_flows(lib_X_output, lib_Y_input, context)
  AND  vuln_class_chain(vuln_class_1, vuln_class_2, escalation)
  THEN concatenative_risk(A, B, context, escalation)
```

**Vulnerability class chains** (non-exhaustive):

| Class 1 (upstream) | Class 2 (downstream) | Chain effect |
|--------------------|---------------------|--------------|
| Input validation bypass | Command injection | RCE |
| Input validation bypass | SQL injection | Data exfiltration |
| Path traversal | File write | Arbitrary file overwrite |
| Deserialization | Code execution | RCE |
| Race condition | Privilege escalation | Privilege escalation |
| Buffer read overrun | Information disclosure | Memory leak → key extraction |
| Authentication bypass | Any | Unauthenticated exploitation |

### 7.3 Cross-language concatenation

Using the existing `CrossLangAnalyzer`, Patch Bridge detects chains that
cross language boundaries:

```
CVE-A in C library (buffer overflow) ──────────┐
                                                │ NIF boundary
CVE-B in Elixir dep (atom exhaustion) ──────────┘

Chain: Malformed input overflows C buffer → corrupted return value
reaches Elixir → dynamic atom creation from corrupted data →
VM-wide atom table exhaustion → denial of service for ALL processes.
```

---

## 8. Mitigation Lifecycle

### 8.1 Registry

Active mitigations are tracked in `.machine_readable/patch-bridge/registry.scm`
and persisted to VeriSimDB as hexads:

```scheme
(mitigation-registry
  (version "0.1.0")
  (project "my-project")
  (mitigations
    (mitigation
      (id "PB-2026-001")
      (cve "CVE-2026-XXXX")
      (dependency "serde_json" "1.0.128")
      (type input-validation)
      (applied "2026-03-21")
      (applied-by "developer@team.com")
      (proof-hash "blake3:abc123...")
      (upstream-fix-watch
        (repo "serde-rs/json")
        (target-version "1.0.129")
        (pr 1847)
        (status merged-awaiting-release))
      (auto-retire-when "serde_json >= 1.0.129")
      (review-by "2026-04-21")
      (files-modified
        ("src/api/handler.rs" "added depth limit check")))))
```

### 8.2 Lifecycle stages

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐
│ APPLIED │────▶│ ACTIVE  │────▶│ RETIRING │────▶│ RETIRED │
└─────────┘     └─────────┘     └──────────┘     └─────────┘
                     │
                     │ review-by date
                     ▼
                ┌──────────┐
                │ STALE    │ (needs re-evaluation)
                └──────────┘
```

- **APPLIED**: Mitigation just deployed. Proof attached. Tests pass.
- **ACTIVE**: Monitoring. Upstream fix watch running.
- **RETIRING**: Upstream fix released. Dependency updated. Verifying
  that removing the mitigation is safe (run tests, check proof).
- **RETIRED**: Mitigation removed. Original code path restored.
  Attestation sealed.
- **STALE**: Review date passed without upstream fix. Re-evaluate:
  is the mitigation still sound? Has the threat landscape changed?

### 8.3 panic-attack assail integration

`panic-attack assail` (pre-commit hook) gains two new checks:

1. **Mitigation presence**: If an active mitigation modifies file X,
   and a commit removes or alters the mitigation code in file X,
   `assail` blocks the commit with:
   ```
   BLOCKED: Commit removes active Patch Bridge mitigation PB-2026-001
   for CVE-2026-XXXX. The upstream fix has not landed yet.
   Run `panic-attack bridge status` for details.
   ```

2. **Stale mitigation**: If a mitigation's `auto-retire-when` condition
   is met (e.g., dependency version bumped past the fix), `assail` warns:
   ```
   INFO: CVE-2026-XXXX is fixed in serde_json 1.0.129 (you have 1.0.129).
   Mitigation PB-2026-001 can be retired.
   Run `panic-attack bridge retire PB-2026-001` to remove safely.
   ```

---

## 9. Adoption Gate

### 9.1 Pre-dependency risk assessment

Before adding a dependency, developers query:

```
$ panic-attack bridge gate serde_json

Adoption Gate: serde_json
==========================

CVE History:
  Total CVEs:      4 (2019–2026)
  Critical:        0
  Unmitigable:     0
  Avg fix time:    3.2 days (excellent)
  Maintainer:      active (dtolnay, 847 contributors)

Vulnerability Class Recurrence:
  Stack overflow (deeply nested): 2 occurrences (recurring pattern)
  Deserialization: 1 occurrence
  Denial of service: 1 occurrence

Your Planned Usage:
  (from flow interview or static analysis)
  Parses untrusted HTTP request bodies → EXPOSED to stack overflow class

Risk Assessment:
  Recurring stack overflow pattern in a crate you'll expose to untrusted input.
  Mitigation available (depth limit). No unmitigable risk.

  Recommendation: PROCEED with mitigation
  Apply: serde_json depth limit (proof available in proven/json-depth-guard)

Alternatives:
  simd-json:    0 CVEs, but no serde compatibility
  sonic-rs:     0 CVEs, serde-compatible, actively maintained
  proven/json:  0 CVEs, formally verified bounds, serde-compatible (recommended)
```

### 9.2 Pattern-based warnings

The gate doesn't just check this dependency's CVE history — it checks the
**vulnerability class pattern** across similar libraries:

```
WARNING: 7 of 12 JSON parsing libraries have had stack overflow CVEs.
This is a systemic vulnerability class in recursive descent parsers.
Consider iterative parsers or proven/json (verified depth-bounded).
```

---

## 10. PanLL Panel Design

### 10.1 Panel identity

| Field | Value |
|-------|-------|
| Panel ID | `PanelPatchBridge` |
| Name | "Patch Bridge" |
| Short name | "PB" |
| Icon | `shield-check` |
| Clade | `security` |
| Has backend | `true` (Tauri commands for CVE feeds, registry, flow persistence) |

### 10.2 Four-file structure

```
src/
├── model/PatchBridgeModel.res       # Types: CVE, Mitigation, FlowChart,
│                                    #   BubbleRating, Classification
├── core/PatchBridgeEngine.res       # Pure: triage logic, bubble calc,
│                                    #   concatenative detection, translation
├── commands/PatchBridgeCmd.res      # Tauri: fetch CVE feeds, read registry,
│                                    #   persist flow charts, check upstream
└── components/PatchBridge.res       # View: dashboard, flow editor,
                                     #   mitigation status, adoption gate
```

### 10.3 Panel layout

```
┌─ Patch Bridge ──────────────────────────────────────────────┐
│                                                             │
│  ┌─ Summary Bar ──────────────────────────────────────────┐ │
│  │ PROJECT: idaptik   DEPS: 47   CVEs: 5                  │ │
│  │ 🔴 Unmitigable: 1  🟡 Mitigated: 2  🟢 Info: 2        │ │
│  │ Sources: 14/14 ✓   Last sweep: 2m ago                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ Tabs ─────────────────────────────────────────────────┐ │
│  │ [Triage] [Flow Map] [Registry] [Gate] [Bubble] [Intel] │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ Triage Tab ───────────────────────────────────────────┐ │
│  │                                                         │ │
│  │  🔴 UNMITIGABLE                                         │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │ CVE-2026-1234  libcrypto  ECDSA timing leak      │   │ │
│  │  │ Flow: auth/session.res → crypto/sign.res         │   │ │
│  │  │ Proof: no mitigation preserves signing + timing  │   │ │
│  │  │ Action: REPLACE → proven/ed25519 (drop-in)       │   │ │
│  │  │ [View Proof] [Show Alternatives] [Replace Now]   │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  │                                                         │ │
│  │  🟡 MITIGATED                                           │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │ CVE-2026-5678  serde_json  stack overflow        │   │ │
│  │  │ Mitigation: depth limit (proof ✓)                │   │ │
│  │  │ Applied: 2026-03-19 by jdaj                      │   │ │
│  │  │ Upstream: PR #847 merged, awaiting release       │   │ │
│  │  │ Auto-retire: when serde_json ≥ 1.0.129           │   │ │
│  │  │ [View Proof] [View Flow] [Check Upstream]        │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  │                                                         │ │
│  │  ⚠ CONCATENATIVE                                       │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │ CVE-2026-3333 × CVE-2026-4444                   │   │ │
│  │  │ libfoo (input bypass) → libbar (priv escalation) │   │ │
│  │  │ Individual: Medium × Medium                      │   │ │
│  │  │ Combined: CRITICAL (proven multiplicative)       │   │ │
│  │  │ [View Chain] [Mitigate Chain]                    │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  │                                                         │ │
│  │  🟢 INFORMATIONAL                                       │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │ CVE-2026-9999  logging-lib  log injection        │   │ │
│  │  │ Reachability: NONE — unreachable in your code    │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ Flow Map Tab ─────────────────────────────────────────┐ │
│  │                                                         │ │
│  │  [Interactive data flow graph]                          │ │
│  │                                                         │ │
│  │  User Input ──▶ API Handler ──▶ serde_json ──▶ DB      │ │
│  │       │                            ⚠ CVE               │ │
│  │       └──▶ File Upload ──▶ image ──▶ Storage            │ │
│  │                             ⚠ CVE                       │ │
│  │                                                         │ │
│  │  Drag to connect. Click node for interview.             │ │
│  │  CVE overlay shows exposure at each node.               │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─ Bubble Tab ───────────────────────────────────────────┐ │
│  │                                                         │ │
│  │  CVE-2026-1234  Sources: ████░░░░░░░░░░  4/14          │ │
│  │  ⚠ BUBBLE: Only Tier 1 sources. VirusTotal community   │ │
│  │    has 3 working exploits not mentioned in NVD.         │ │
│  │    oss-security thread has additional attack vectors.   │ │
│  │                                                         │ │
│  │  CVE-2026-5678  Sources: ██████████████  14/14 ✓       │ │
│  │  Full coverage. No divergence.                          │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 11. Upstream Feedback Loop

When Patch Bridge generates a proven mitigation, it can contribute back:

### 11.1 Automated upstream PR

```
$ panic-attack bridge upstream CVE-2026-XXXX

Generating upstream contribution for CVE-2026-XXXX...

Mitigation: depth-limited JSON parsing
Proof: MitigationSound (verified by Idris2 type checker)
Target: serde-rs/json

Draft PR:
  Title: "Fix CVE-2026-XXXX: add configurable depth limit"
  Body:
    This PR addresses CVE-2026-XXXX (stack overflow on deeply nested input)
    by adding a configurable depth limit to the parser.

    This fix has been formally verified using Idris2 dependent types:
    - Soundness: all inputs that trigger the overflow are rejected
    - Completeness: all valid JSON within the depth limit is accepted
    - Proof artifact: attached as proof/depth-limit-soundness.idr

    Generated by Patch Bridge (panic-attack).

  Open PR? [y/N]
```

### 11.2 Proof export format

Proofs are exported in a format that upstream maintainers can verify
independently, even without Idris2:

```
proof/
├── depth-limit-soundness.idr     # Idris2 source (machine-checkable)
├── depth-limit-soundness.md      # Human-readable proof sketch
├── test-vectors.json             # Concrete test cases derived from proof
└── attestation.a2ml              # Cryptographic attestation (Ed25519)
```

The test vectors are generated from the proof — if the upstream maintainer
doesn't use Idris2, they can at least run the test vectors to gain
confidence in the fix.

---

## 12. BoJ Cartridge

A BoJ cartridge `patch-bridge` provides continuous monitoring:

### 12.1 Capabilities

- **Scheduled CVE sweep**: Poll all source tiers on configurable intervals
- **Webhook receiver**: GitHub Security Advisory webhooks for instant notification
- **Registry sync**: Keep VeriSimDB hexads in sync with active mitigations
- **Upstream watch**: Monitor dependency release feeds for fix availability
- **Alert routing**: Push unmitigable/concatenative alerts to notification channels

### 12.2 Cartridge manifest

```json
{
  "name": "patch-bridge",
  "version": "0.1.0",
  "description": "CVE intelligence, mitigation lifecycle, and formal verification",
  "triggers": ["schedule:6h", "webhook:github-security", "manual"],
  "outputs": ["panll:event-chain", "verisimdb:hexad", "notify:alert"],
  "dependencies": ["panic-attack >= 2.1.0"]
}
```

---

## 13. Proven Repository Integration

The `proven/` repository contains formally verified implementations.
Patch Bridge uses it as a **mitigation source**:

```
CVE vulnerability class    →  proven/ alternative
───────────────────────────────────────────────
JSON stack overflow        →  proven/json (depth-bounded parser)
XML XXE                    →  proven/xml (XXE-immune by construction)
ECDSA timing leak          →  proven/ed25519 (constant-time, verified)
Buffer overflow            →  proven/bounded-buffer (length-indexed)
Path traversal             →  proven/safe-path (normalisation proof)
Deserialization gadget     →  proven/safe-deserialize (type-restricted)
```

When a CVE maps to a vulnerability class with a proven/ alternative,
Patch Bridge recommends the replacement with a compatibility assessment.

---

## 14. Implementation Priorities

### Phase 1 — Foundation (panic-attack extension)

1. `src/bridge/mod.rs` — Module structure and public API
2. `src/bridge/intelligence.rs` — OSV API integration (simplest feed first)
3. `src/bridge/classify.rs` — Three-way triage using existing kanren engine
4. `src/bridge/registry.rs` — SCM file-based mitigation tracking
5. New subcommands: `bridge intel`, `bridge triage`, `bridge status`

### Phase 2 — Intelligence expansion

6. `src/bridge/intelligence.rs` — Add NVD, GHSA, RustSec feeds
7. `src/bridge/bubble.rs` — Source coverage and divergence detection
8. `src/bridge/gate.rs` — Pre-adoption risk assessment
9. New subcommands: `bridge gate`, `bridge bubble`

### Phase 3 — Formal verification

10. `src/abi/Bridge/Classify.idr` — Idris2 mitigation soundness types
11. `src/abi/Bridge/Concatenate.idr` — Multiplicative risk proofs
12. `ffi/zig/src/bridge.zig` — FFI bridge for proof verification results
13. Integration: Idris2 proof artifacts attached to mitigations

### Phase 4 — Developer experience

14. `src/bridge/flow.rs` — Developer interview mode (CLI)
15. `src/bridge/translate.rs` — Cross-domain threat translation
16. PanLL panel: four-file ReScript panel in PanLL repo
17. `panic-attack assail` integration (mitigation presence + stale checks)

### Phase 5 — Ecosystem integration

18. `src/bridge/retire.rs` — Upstream fix watch + auto-retirement
19. `src/bridge/upstream.rs` — PR generation with proof export
20. `src/bridge/concatenate.rs` — Full concatenative analysis engine
21. BoJ cartridge for continuous monitoring
22. VeriSimDB hexad persistence for mitigation registry
23. Multi-source Tier 3 feeds (oss-security, academic, commit analysis)

---

## 15. What Makes This Different

| Capability | Existing tools | Patch Bridge |
|-----------|---------------|-------------|
| Detect CVEs | ✓ (Trivy, Grype, Snyk) | ✓ |
| Suggest fix version | ✓ | ✓ |
| Multi-source intelligence | Partial (1–2 sources) | ✓ (14+ sources, 3 tiers) |
| Bubble detection | ✗ | ✓ |
| Contextual reachability | Partial (Snyk, some) | ✓ (kanren taint engine) |
| Cross-language chains | ✗ | ✓ (kanren crosslang engine) |
| Concatenative danger | ✗ | ✓ (CVE×CVE interaction proofs) |
| Generate mitigation | ✗ | ✓ |
| Prove mitigation works | ✗ | ✓ (Idris2 dependent types) |
| Prove unmitigability | ✗ | ✓ (impossibility proofs) |
| Mitigation lifecycle | ✗ | ✓ (apply → monitor → retire) |
| Auto-retire on fix | ✗ | ✓ |
| Block mitigation removal | ✗ | ✓ (assail pre-commit) |
| Developer interview | ✗ | ✓ (flow chart artifacts) |
| Adoption gate | Partial (Snyk Advisor) | ✓ (pattern + class analysis) |
| Cross-domain translation | ✗ | ✓ |
| Upstream feedback | ✗ | ✓ (proven PRs with proofs) |
| Visual panel (IDE) | ✗ | ✓ (PanLL panel) |

---

## 16. Open Questions

1. **Proof granularity**: How specific should Idris2 proofs be? Per-CVE
   proofs are most valuable but most expensive. Per-vulnerability-class
   proofs are reusable but less precise. Likely: class-level proofs with
   CVE-specific test vectors.

2. **VirusTotal API limits**: Free tier allows 4 requests/minute. May
   need premium for continuous monitoring. Alternative: cache aggressively,
   batch queries via BoJ cartridge.

3. **Interview fatigue**: Developers won't answer 47 questions. Prioritise
   by: (a) dependencies with active CVEs, (b) dependencies that handle
   untrusted input, (c) dependencies at trust boundaries. Target ≤10
   questions per session.

4. **Upstream reception**: Will maintainers accept PRs with Idris2 proofs
   they can't read? Mitigate by: always include human-readable proof
   sketch + concrete test vectors. The proof is bonus, not requirement.

5. **False positive management**: Contextual unreachability analysis may
   have false negatives (says "unreachable" but isn't). Conservative
   default: if uncertain, classify as mitigable rather than informational.
   kanren context-facts (planned) will reduce FP rate.

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **Adoption gate** | Pre-dependency risk assessment |
| **Bubble rating** | Source coverage metric per CVE (like Ground News media bias) |
| **Concatenative danger** | Risk multiplication when CVEs share trust boundaries |
| **Flow chart artifact** | Persisted data-flow model from developer interview |
| **Mitigation** | A layered control that prevents exploitation of a specific CVE |
| **Patch Bridge** | This system — bridges the gap between CVE disclosure and upstream fix |
| **Soundness proof** | Idris2 proof that a mitigation prevents exploitation |
| **Unmitigability proof** | Idris2 proof that no mitigation can prevent exploitation |
| **Upstream feedback** | Contributing proven mitigations back to dependency maintainers |

## Appendix B: Related Work

- **Snyk**: Detection + curated patches (manual, no proofs, no lifecycle)
- **Trivy/Grype**: Detection only (no mitigation, no context)
- **OSV-Scanner**: Detection with OSV database (Google, comprehensive, no mitigation)
- **Renovate/Dependabot**: Automated version bumps (post-fix only, no bridge period)
- **ModSecurity/OWASP CRS**: Virtual patching at WAF level (network only, no compile-time)
- **RASP tools**: Runtime protection (overhead, no formal guarantees)
- **OSS-Fuzz/ClusterFuzz**: Fuzzing finds bugs (detection, not mitigation)
- **Semgrep**: Pattern-based scanning (detection, some autofix, no proofs)
- **EPSS**: Exploit probability scoring (better than CVSS, but still not contextual)
