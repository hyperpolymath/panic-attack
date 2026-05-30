<!-- SPDX-License-Identifier: MPL-2.0 -->
<!--
  Draft comment for posting on panic-attack#33 after PR feat/chapel-ci-strict-gates merges.
  Not auto-posted; the PR author or a maintainer pastes this onto the issue.
-->

# Cross-link: Chapel-side hexad producer is now CI-gated (#33 / PR `feat/chapel-ci-strict-gates`)

`Temporal.chpl::writeTemporalHexad` is the Chapel-side producer for
mass-panic temporal snapshots, which feed the VeriSimDB hexad readers
this issue tracks (S1 per-finding, S2 campaign-state, S3 query).

PR `feat/chapel-ci-strict-gates` lands six strict CI gates on the
`chapel/` tree and the Chapel↔Rust contract:

| Gate | What it catches |
|------|------------------|
| `chapel-parse-check` | Chapel syntax regressions in any of 4 modules + smoke |
| `chapel-build` | Cross-module build break (stock ubuntu .deb, no toolbox) |
| `chapel-smoke` | `RepoResult → SystemImage → JSON` data-flow regressions |
| `chapel-e2e` | mass-panic full pipeline end-to-end (single-locale) |
| `chapel-cli-contract` | Rust clap drift breaking Chapel's argv shape |
| `chapel-rust-diff` | Aggregate divergence between rayon and Chapel paths |

The four silent-loss fixes (`path`, `high_count`, `error`,
`category_breakdown` previously dropped by `writeNodeJson`) mean
the producer side now preserves every ImageNode field the hexad
consumer can persist. Mapping of Chapel writers → hexad facets:

* `provenance` ← `Temporal.chpl` (tool, version, locales, scan_surface)
* `temporal` ← `Temporal.chpl` (timestamp, sequence_number, label)
* `semantic` ← `Imaging.chpl` (global_health, global_risk, totals)
* `structural` ← `Imaging.chpl` (totalFiles, totalLines, riskDistribution)
* `document` ← `Imaging.chpl::writeSystemImageJson` (full SystemImage)

Out of scope here, tracked for Wave 2:

* True multi-locale CI (`CHPL_COMM=gasnet` install).
* Subprocess kill-path on hang.
* NFS journal lock semantics.
* BoJ-estate scheduler benchmark to back the "~5–15% slower" claim.

See `docs/adr/0001-chapel-distributed-scanner.md` for the full
rollout decision record.
