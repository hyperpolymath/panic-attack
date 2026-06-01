---
name: Bug report
about: Report a panic-attack defect (false-positive rule, runtime crash, schema breakage, missed detection)
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what went wrong. If this is a detector firing where it shouldn't (false positive) or NOT firing where it should (false negative), say so explicitly.

**Reproduction**
Minimal steps to reproduce:
1. `panic-attack <subcommand> <args>` …
2. Against fixture / repo at … (link or attach minimal sample)
3. Observed: …
4. Expected: …

**Sample output**
If applicable, paste the JSON / A2ML report excerpt that demonstrates the issue:

```
<paste output here>
```

**Environment**
- panic-attack version: `panic-attack --version` →
- Rust toolchain: `rustc --version` →
- OS / arch:
- Target source language(s) under scan (Rust / Haskell / Idris2 / Coq / Lean / Agda / Isabelle / Chapel / …):
- Sub-command involved (`assail` / `bridge` / `verisimdb` / `assault` / …):

**Additional context**
- Has the same input run cleanly in a prior version? If so, which?
- Any relevant config (`.hypatia-ignore`, `.trusted-base-ignore`, `audits/assail-classifications.a2ml`)?
- Suspected detector / file in `src/assail/analyzer.rs` or similar?
