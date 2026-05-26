# PROOF-NEEDS.md — panic-attack

## Current State

- **src/abi/*.idr**: 3 files — `Types.idr`, `PatternCompleteness.idr` (PA1 ✅ 2026-04-11), `ClassificationSoundness.idr` (PA2 ✅ 2026-04-11)
- **Dangerous patterns**: 0 in own code (3 references are in the analyzer that DETECTS believe_me in other repos); 282 `unwrap()` calls
- **LOC**: ~31,700 (Rust)
- **ABI layer**: Idris2 with completeness + soundness proofs

## Completed Proofs

| Proof | File | What it proves |
|-------|------|---------------|
| PA1 Pattern detection completeness | `src/abi/PatternCompleteness.idr` | All 49 `Lang` constructors have an analyzer; all 20 `WPCategory` constructors have at least one detector; cross-language checks applied unconditionally to all languages. `completeScanForAll` is the top-level theorem. |
| PA2 Classification soundness | `src/abi/ClassificationSoundness.idr` | Severity (Low/Medium/High/Critical) is totally ordered (`LTE`); `maxSeverity` is commutative and idempotent; numeric ABI encoding preserves the ordering. |

## What Still Needs Proving

| Component | What | Why |
|-----------|------|-----|
| Bridge reachability soundness | Reachability analysis is sound (no reachable dep wrongly classified as phantom) | Unreachable code marked reachable wastes effort; reachable missed = security gap |
| Attestation chain unforgeability | Intent/evidence/seal triple is cryptographically bound; tampering detectable | Tampered attestations break trust chain |
| Kanren taint analysis | Taint propagation tracks all tainted data flows | Missed taint flow means missed vulnerability |

## Recommended Prover

**Idris2** — Already in use. Taint analysis correctness proofs could use **Agda** with relational semantics. The 282 unwrap() calls are a significant debt (but separate from the proof obligations).

## Priority

**MEDIUM** (was HIGH) — PA1 and PA2 completed 2026-04-11. The highest-risk false-negative scenario (analyzer dispatch completeness) is now formally proved. Remaining proofs are deeper semantic properties.
