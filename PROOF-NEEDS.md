# PROOF-NEEDS.md — panic-attacker

## Current State

- **src/abi/*.idr**: YES — `Types.idr`
- **Dangerous patterns**: 0 in own code (3 references are in the analyzer that DETECTS believe_me in other repos); 282 `unwrap()` calls
- **LOC**: ~31,700 (Rust)
- **ABI layer**: Minimal Idris2 types

## What Needs Proving

| Component | What | Why |
|-----------|------|-----|
| Assail analyzer soundness | Pattern detection has no false negatives for critical patterns | Security scanner missing a vulnerability is its worst failure mode |
| Assail analyzer completeness | No false positives for clean code | False positives erode trust and cause alert fatigue |
| SARIF report correctness | Generated SARIF is well-formed and semantically correct | Malformed SARIF breaks CI/CD pipeline integration |
| Bridge classify | CVE classification is correct | Wrong CVE classification leads to wrong mitigation |
| Bridge reachability | Reachability analysis is sound | Unreachable code marked reachable wastes effort; reachable code missed is a security gap |
| Kanren taint analysis | Taint propagation tracks all tainted data flows | Missed taint flow means missed vulnerability |
| Attestation chain | Attestation envelope integrity is unforgeable | Tampered attestations break trust chain |
| Bridge lockfile parsing | Lockfile parser extracts correct dependency versions | Wrong versions mean wrong vulnerability matching |

## Recommended Prover

**Idris2** — Extend `src/abi/Types.idr` with analyzer soundness/completeness types. Taint analysis correctness proofs could use **Agda** with relational semantics. The 282 unwrap() calls are a significant debt.

## Priority

**HIGH** — panic-attacker is the pre-commit security scanner used across all repos. If it has false negatives, vulnerabilities slip through the entire ecosystem. Analyzer soundness is the single most important proof in this repo.
