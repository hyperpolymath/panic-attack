<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# Release Prep Checklist

This checklist is for shipping the `amuck`/`abduct`/`adjudicate`/`axial` + A2ML report-bundle work without pulling unrelated tree changes.

## 1. Validation Gates

Run before tagging or publishing:

```bash
cargo fmt --check
cargo test -q
cargo run --quiet -- help a2ml-export
cargo run --quiet -- help a2ml-import
```

## 2. A2ML Roundtrip Smoke Tests

Minimal end-to-end checks:

```bash
panic-attack a2ml-export --kind assail reports/assail.json --output /tmp/assail.a2ml
panic-attack a2ml-import /tmp/assail.a2ml --output /tmp/assail.roundtrip.json --kind assail

panic-attack a2ml-export --kind attack reports/attack-results.json --output /tmp/attack.a2ml
panic-attack a2ml-import /tmp/attack.a2ml --output /tmp/attack.roundtrip.json --kind attack

panic-attack a2ml-export --kind ambush reports/ambush.json --output /tmp/ambush.a2ml
panic-attack a2ml-import /tmp/ambush.a2ml --output /tmp/ambush.roundtrip.json --kind ambush
```

Repeat for `assault`, `amuck`, `abduct`, `adjudicate`, and `axial` when test fixtures are available.

## 3. Curated Staging Set

Stage only the feature/docs files for this stream:

```bash
git add \
  src/a2ml/mod.rs \
  src/main.rs \
  src/assail/mod.rs \
  src/assail/analyzer.rs \
  src/assail/patterns.rs \
  src/attack/mod.rs \
  src/attack/executor.rs \
  src/attack/profile.rs \
  src/attack/strategies.rs \
  src/kanren/core.rs \
  src/kanren/crosslang.rs \
  src/kanren/rules.rs \
  src/kanren/strategy.rs \
  src/report/mod.rs \
  src/report/generator.rs \
  src/report/diff.rs \
  src/report/output.rs \
  src/report/formatter.rs \
  README.md \
  man/panic-attack.1 \
  docs/codebase-annotations.md \
  docs/release-prep.md
```

Then verify:

```bash
git diff --cached --stat
git diff --cached
```
