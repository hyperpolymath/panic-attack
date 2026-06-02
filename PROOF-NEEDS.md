# PROOF-NEEDS.md — panic-attack

## Current State

- **src/abi/*.idr**: 4 files — `Types.idr`, `PatternCompleteness.idr` (PA1 ✅ 2026-04-11), `ClassificationSoundness.idr` (PA2 ✅ 2026-04-11), `Stripping.idr` (PROOF-PROGRAMME Layer 1.0 partial — base cases proved, slash-slash inductive open)
- **Dangerous patterns**: 0 in own code (3 references are in the analyzer that DETECTS believe_me in other repos); 282 `unwrap()` calls
- **LOC**: ~31,700 (Rust)
- **ABI layer**: Idris2 with completeness + soundness proofs + Layer-1.0 stripping foundation

## Completed Proofs

| Proof | File | What it proves |
|-------|------|---------------|
| PA1 Pattern detection completeness | `src/abi/PatternCompleteness.idr` | All 49 `Lang` constructors have an analyzer; all 20 `WPCategory` constructors have at least one detector; cross-language checks applied unconditionally to all languages. `completeScanForAll` is the top-level theorem. |
| PA2 Classification soundness | `src/abi/ClassificationSoundness.idr` | Severity (Low/Medium/High/Critical) is totally ordered (`LTE`); `maxSeverity` is commutative and idempotent; numeric ABI encoding preserves the ordering. |
| Layer 1.0 partial — stripping foundation | `src/abi/Stripping.idr` | (a) `stripLineCommentBody` always produces `IsStrippedBody`-shaped output (Qed); (b) base cases of `stripLineCommentsIdempotent`: empty input + non-`/`-headed input (Qed). Three concrete sanity-check theorems. Open: the slash-slash inductive case below. |

## What Still Needs Proving

| Component | What | Why |
|-----------|------|-----|
| **Layer 1.0 — stripIsIdentityOnStrippedBody (slash-slash closure)** | `stripLineComments` applied to any `IsStrippedBody xs` returns `xs` unchanged | Required to close the `'/' :: '/' :: rest` case of `stripLineCommentsIdempotent`. Without it, all Layer-1.1..1.25 per-category proofs would have to re-verify that comments don't re-introduce themselves. |
| **Layer 1.0 — stripBlockComments + Strings** | Block-comment (`/* */`) and string-literal (`"..."`) strippers with the same shape lemma + idempotence. Composition theorem. | Three slices: `Stripping_Block.idr`, `Stripping_Strings.idr`, `Stripping_Composition.idr`. |
| **Layer 1.0 — position preservation** | For every index `i` where `cs[i]` is OUTSIDE every comment/string, `strip cs ! i = cs[i]` | Justifies the analyzer reporting locations against the stripped view as if they were original source. |
| Bridge reachability soundness | Reachability analysis is sound (no reachable dep wrongly classified as phantom) | Unreachable code marked reachable wastes effort; reachable missed = security gap |
| Attestation chain unforgeability | Intent/evidence/seal triple is cryptographically bound; tampering detectable | Tampered attestations break trust chain |
| Kanren taint analysis | Taint propagation tracks all tainted data flows | Missed taint flow means missed vulnerability |

## Recommended Prover

**Idris2** — Already in use. Taint analysis correctness proofs could use **Agda** with relational semantics. The 282 unwrap() calls are a significant debt (but separate from the proof obligations).

## Priority

**MEDIUM** (was HIGH) — PA1 and PA2 completed 2026-04-11. The highest-risk false-negative scenario (analyzer dispatch completeness) is now formally proved. Remaining proofs are deeper semantic properties.
