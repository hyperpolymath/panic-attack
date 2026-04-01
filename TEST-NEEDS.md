# TEST-NEEDS.md — panic-attacker

> Generated 2026-03-29 by punishing audit.

## Current State

| Category     | Count | Notes |
|-------------|-------|-------|
| Unit tests   | ~70   | All inline `#[test]`: strategies(3), engine(9), rules(3), taint(2), crosslang(3), strategy(4), core(15), storage(2), a2ml(9), timeline(15), plus others |
| Integration  | 0     | None |
| E2E          | 0     | None |
| Benchmarks   | 1     | benches/scan_bench.rs — REAL benchmarks (language detection, family classification, pattern matching, full pipeline) |

**Source modules:** ~62 Rust source files covering: attack strategies, signature engine/rules, kanren (taint analysis, crosslang, strategy, core), storage, a2ml parsing, ambush timeline, CLI, patch-bridge integration.

## What's Missing

### P2P (Property-Based) Tests
- [ ] Signature matching: property tests for pattern match correctness (no false negatives on known-bad patterns)
- [ ] Kanren core: logic programming property tests (query soundness)
- [ ] Taint analysis: property tests for taint propagation invariants
- [ ] A2ML parsing: arbitrary A2ML input fuzzing

### E2E Tests
- [ ] Full scan: target repo -> detect languages -> apply rules -> generate report
- [ ] Ambush: timeline creation -> event detection -> alert generation
- [ ] Cross-language analysis: multi-language project scan
- [ ] CLI: all subcommands with real project input

### Aspect Tests
- **Security:** No integration tests for the security scanner itself. Can it be bypassed? Can malicious code evade detection? — This is a security tool with ZERO security evasion tests
- **Performance:** Benchmark exists and is REAL (good). Missing: memory usage under large repos, scaling with repo size
- **Concurrency:** No tests for parallel file scanning, concurrent rule evaluation
- **Error handling:** No tests for malformed source files, binary files in scan path, permission denied, symlink loops

### Build & Execution
- [ ] `cargo test` verification
- [ ] `cargo bench` execution
- [ ] CLI smoke test suite

### Benchmarks Needed (Existing + Missing)
- [x] Language detection speed (EXISTS)
- [x] Pattern matching throughput (EXISTS)
- [ ] Full repository scan time vs repo size
- [ ] Memory usage profile
- [ ] Taint analysis scaling
- [ ] Rule evaluation throughput per language

### Self-Tests
- [ ] Scan its own source code (eat own dogfood)
- [ ] Signature database integrity check
- [ ] Rule completeness verification (all supported languages have rules)

## Priority

**HIGH.** 62 modules with ~70 inline tests is actually decent unit coverage (over 1 test per module average). The benchmark is real and useful. BUT: zero integration tests, zero E2E tests, and zero security evasion tests for a security scanning tool. The kanren core has 15 tests which is good. The gap is in integration — the pieces are tested individually but never together.

## FAKE-FUZZ ALERT

- `tests/fuzz/placeholder.txt` is a scorecard placeholder inherited from rsr-template-repo — it does NOT provide real fuzz testing
- Replace with an actual fuzz harness (see rsr-template-repo/tests/fuzz/README.adoc) or remove the file
- Priority: P2 — creates false impression of fuzz coverage
