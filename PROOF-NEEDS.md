<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->
# PROOF-NEEDS.md — panic-attack

## Current State

- **src/abi/*.idr**: 5 files — `Types.idr`, `PatternCompleteness.idr` (PA1 ✅ 2026-04-11), `ClassificationSoundness.idr` (PA2 ✅ 2026-04-11), `Stripping.idr` (PROOF-PROGRAMME Layer 1.0 line-comment slice ✅ 2026-06-02 — multi-comment semantics + slash-slash closure both Qed via mutual-recursive `bodyIsFixedPoint`), `AttestationUnforgeability.idr` (PROOF-PROGRAMME §3.2 ✅ 2026-06-04 — conditional unforgeability from Ed25519 EUF-CMA + chain-hash collision-resistance hypotheses)
- **Dangerous patterns**: 0 in own code (3 references are in the analyzer that DETECTS believe_me in other repos); 282 `unwrap()` calls
- **LOC**: ~31,700 (Rust)
- **ABI layer**: Idris2 with completeness + soundness proofs + Layer-1.0 stripping foundation

## Completed Proofs

| Proof | File | What it proves |
|-------|------|---------------|
| PA1 Pattern detection completeness | `src/abi/PatternCompleteness.idr` | All 49 `Lang` constructors have an analyzer; all 20 `WPCategory` constructors have at least one detector; cross-language checks applied unconditionally to all languages. `completeScanForAll` is the top-level theorem. |
| PA2 Classification soundness | `src/abi/ClassificationSoundness.idr` | Severity (Low/Medium/High/Critical) is totally ordered (`LTE`); `maxSeverity` is commutative and idempotent; numeric ABI encoding preserves the ordering. |
| Layer 1.0 line-comment idempotence | `src/abi/Stripping.idr` | **2026-06-02 close-out (issue #113)**: corrects PR #111's single-comment model to multi-comment via mutual recursion (`stripLineComments ↔ stripLineCommentBody` — body calls back into main after each preserved newline). Qed-closes `stripLineCommentsIdempotent` for ALL cases including the slash-slash inductive via the load-bearing `bodyIsFixedPoint` lemma proved by mutual induction with the main theorem. 7 sanity-check theorems including the two-comments-on-different-lines case PR #111 silently mis-stripped. |
| Attestation chain unforgeability | `src/abi/AttestationUnforgeability.idr` | **PROOF-PROGRAMME §3.2 (2026-06-04, issue #123)**: models the intent→evidence→seal chain (`chain_hash = H(intent‖evidence‖report)`, Ed25519-signed) with the cryptographic facts as a `parameters` block (hypotheses, **not** `postulate`). Under `%default total` Qed-closes `integrity` (tampering any phase invalidates the seal), `authenticity` (a verifying seal comes from the matching secret key), `nonRepudiation` (a genuine seal verifies), plus 2 corollaries. Conditional on chain-hash collision-resistance + Ed25519 EUF-CMA (message- and signer-binding) + signature correctness. |
| Hexad↔Octad persistence round-trip | `src/storage/mod.rs` (proptest) | **PROOF-PROGRAMME §3.1 (2026-06-04, #122)**: `hexad_json_roundtrip_is_identity` proves the on-disk serde round-trip (`write_*_hexad` → `load_hexad_dir`) is the identity on the hexad JSON. The gateway octad projection is lossy by design, so the faithful integrity property is the persistence round-trip, not the literal hexad↔octad map. |

## What Still Needs Proving

| Component | What | Why |
|-----------|------|-----|
| **Layer 1.0 — stripBlockComments + Strings + Composition + Position-Preservation** (issue #114) | Block-comment (`/* */`) and string-literal (`"..."`) strippers with same mutual-recursive shape; composition theorem proving the full pipeline is idempotent given each component is; position-preservation theorem justifying analyzer location-reporting against the stripped view as if it were original-source. | Four slices: `Stripping_Block.idr`, `Stripping_Strings.idr`, `Stripping_Composition.idr`, `Stripping_PositionPreservation.idr`. |
| Bridge reachability soundness | Reachability analysis is sound (no reachable dep wrongly classified as phantom) | Unreachable code marked reachable wastes effort; reachable missed = security gap |
| Kanren taint analysis | Taint propagation tracks all tainted data flows | Missed taint flow means missed vulnerability |

## Recommended Prover

**Idris2** — Already in use. Taint analysis correctness proofs could use **Agda** with relational semantics. The 282 unwrap() calls are a significant debt (but separate from the proof obligations).

## Priority

**MEDIUM** (was HIGH) — PA1 and PA2 completed 2026-04-11. The highest-risk false-negative scenario (analyzer dispatch completeness) is now formally proved. Remaining proofs are deeper semantic properties.
