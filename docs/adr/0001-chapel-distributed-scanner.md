<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# ADR 0001 — Chapel as a detachable distributed-scanner harness

* **Status:** Accepted (Wave 1 landed via PR `feat/chapel-ci-strict-gates`)
* **Date:** 2026-05-30
* **Refs:** [issue #33](https://github.com/hyperpolymath/panic-attack/issues/33) (VeriSimDB hexad persistence S1–S3), `chapel/README.md`, `.github/workflows/chapel-ci.yml`

## Context

`panic-attack` ships three deployment modes (see `.claude/CLAUDE.md`):

1. **Standalone** — single binary, zero dependencies, USB-stick-portable.
2. **Panicbot** — automated JSON scanning in CI (gitbot-fleet, GH Actions).
3. **Mass-panic** — org-scale batch scanning across many repos.

Mode 3 has two layers:

* `src/assemblyline.rs` — rayon-parallel single-machine batch scanner.
* `chapel/` — multi-machine fan-out built on Chapel locales, spawning the
  `panic-attack` Rust binary on each worker via `Subprocess`.

Until this PR, the Chapel layer was prose-only: 2354 LOC of well-structured
code with no CI, no smoke test, and no contract enforcement against the
Rust binary it shells out to. Every Subprocess call assumed the Rust
side's flag set matched what `MassPanic.chpl::buildCommandArgs` emits;
nothing detected silent drift. The data path from `RepoResult` →
`SystemImage` → JSON had four silent losses (`path`, `highCount`,
`error`, `categoryBreakdown` all populated but never serialised by
`Imaging.chpl::writeNodeJson`). The README claimed a `--resume` /
`--scheduler=static` interaction that was implemented as a warning
ignored at runtime.

## Decision

### Detachability is the load-bearing principle

The Chapel layer is **strictly outboard**. Removing `chapel/` from the
repo must leave the Rust build green and the single-machine USB-stick
experience intact. Therefore:

* No Cargo dependency on Chapel.
* No `src/` references to `chapel/` paths.
* The Rust binary gains no Chapel-specific flags; the new
  `describe-contract` subcommand is framed as a **general orchestrator
  capability** (useful to Nextflow / Airflow / Slurm / shell scripts /
  any future driver), not a Chapel bridge.
* Path triggers on `.github/workflows/chapel-ci.yml` are scoped to
  `chapel/**` + the Rust contract-defining files (`src/main.rs`,
  `src/types.rs`, `Cargo.toml`, `Cargo.lock`). A pure-Rust PR that
  doesn't touch these paths never wakes Chapel CI.

### CI gates land six strict jobs

No `continue-on-error` anywhere. Failure on any of the six fails the PR:

1. `chapel-parse-check` — `chpl --parse-only` on every module + smoke.
2. `chapel-build` — `just chapel-build-ci` (toolbox-free, .deb install).
3. `chapel-smoke` — `chapel/smoke/two_repo_smoke` exercises the
   `RepoResult → SystemImage → JSON` data flow + asserts the four
   silent-loss fields appear.
4. `chapel-e2e` — `mass-panic --numLocales=1` against a synthetic
   2-repo manifest. (True `-nl 2` requires `CHPL_COMM=gasnet`; the
   stock .deb ships `CHPL_COMM=none`. Tracked for Wave 2.)
5. `chapel-cli-contract` — runs `panic-attack describe-contract` and
   asserts the live JSON matches `chapel/tests/expected_contract.json`.
6. `chapel-rust-diff` — rayon assemblyline vs Chapel single-locale on
   the same synthetic corpus; aggregates (`total_weak_points`,
   `total_critical`, `repos_scanned`) must agree.

### Bug fixes that were in scope here

* `Imaging.chpl::writeNodeJson` now serialises `path`, `high_count`,
  `error`, `category_breakdown` (with JSON-escape) — four fields that
  were populated in memory but dropped from the SystemImage JSON.
* `MassPanic.chpl::selectAndAnnounceScheduler` now hard-fails when
  `--scheduler=static --resume` is combined (previously: warning then
  proceeded silently).
* `MassPanic.chpl::buildCommandArgs` adjudicate mode now passes `--quiet`
  for consistency with assail / assault / ambush (was the only mode
  that didn't, risking banner-bleed into Chapel's JSON parser).
* `journalEscape` renamed local `out` → `buf` — Chapel 2.8.0 parses
  `out` as the intent keyword more strictly than older versions.

### Bug fixes deferred (Wave 2 trackers)

* **Subprocess hang kill path** — `panic-attack --timeout=N` is currently
  the only safeguard; Chapel `sub.wait()` blocks indefinitely if the
  subprocess ignores the timeout. Needs a Chapel-side grace-period
  loop + SIGKILL.
* **NFS journal lock semantics** — the journal directory assumes POSIX
  `flock` works; NFSv3 violates this. Needs a startup probe + warning.
* **True multi-locale CI** — requires installing Chapel built with
  `CHPL_COMM=gasnet`, which the stock `.deb` doesn't ship. Needs either
  a multilocale Chapel build step or a maintained `chapel-multilocale`
  package on the runner.
* **`describe-contract` SHA-pin for the .deb download** — workflow
  currently trusts the HTTPS endpoint at `chapel-lang/chapel` releases.
  Add SHA256 verification before promoting Chapel to a production gate.
* **Real BoJ-estate scheduler benchmark** — README claims queue is
  ~5–15% slower; this is theoretical. A 350-repo, 2-locale measurement
  is Wave 2 work.
* **`buildCommandArgs` callsite consolidation** — `MassPanic.chpl` has
  five sites that spawn the Rust binary; one (`buildCommandArgs`) is
  the canonical builder. Three other sites (`runAttackPass`,
  `runAdjudicatePass`, `computeFingerprint`) bypass it. Consolidating
  to a single helper is a refactor that doesn't belong in the CI PR.

## Relationship to issue #33 (VeriSimDB hexad persistence S1–S3)

Chapel's `Temporal.chpl::writeTemporalHexad` is the **producer** for
mass-panic temporal snapshots; the Rust-side hexad reader in
`src/storage/mod.rs` is the **consumer**. Issue #33's S1/S2/S3 stages
landed in the Rust side. This PR makes the producer side CI-enforced:
any change to either the Chapel writer or the Rust hexad schema that
breaks the contract is caught by `chapel-rust-diff` (aggregate parity)
or `chapel-cli-contract` (CLI shape). The four silent-loss fixes
ensure the producer no longer drops fields the hexad would otherwise
have persisted.

## Consequences

* `chapel/` is now a load-bearing CI tree. New Chapel module additions
  must compile under `chpl --parse-only` and pass the smoke (a one-line
  assertion can be added per new field via `chapel/smoke/two_repo_smoke.chpl`).
* Any clap flag rename in `src/main.rs` that affects the five Chapel-used
  modes (assail, assault, ambush, attack, adjudicate) will fail
  `chapel-cli-contract`. The fix is to update both clap and
  `chapel/tests/expected_contract.json` in the same PR.
* Pure-Rust PRs that don't touch the trigger paths skip chapel-ci entirely;
  Chapel CI failure cannot block a Rust-only release.
* Wave 2 enables real-cluster validation (`-nl 16+` on actual nodes).

## Alternatives considered

* **Promote Chapel to a Rust dependency** — rejected. Would break
  detachability and the USB-stick experience.
* **Merge `assemblyline.rs` into Chapel** — rejected. Rayon is the
  right tool for single-machine, Chapel for cross-machine. They are
  not redundant.
* **Use clap's `CommandFactory` reflection to auto-generate the contract
  fixture** — adopted for the `describe-contract` handler itself
  (auto-syncs with clap). Rejected for the fixture (`expected_contract.json`)
  because the fixture defines what Chapel *requires*, not what Rust
  currently *offers*; keeping it static documents the contract surface
  Chapel depends on.
