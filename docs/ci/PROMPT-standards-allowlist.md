<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# Prompt for `standards` (and the estate settings applier): the allowlist does not cover a renamed repository

Copy everything below the line into a session on
`metadatastician/standards` (or into the repo-settings applier's queue). It is
written to be self-contained: it names the evidence, the change, and the
acceptance test.

---

## Problem

Six caller repositories — `hyperpolymath/panic-attack` among them — have
`pull_request` workflows whose only job is

```yaml
uses: hyperpolymath/standards/.github/workflows/rust-ci-reusable.yml@333b06a0…
```

Every one of those runs concludes `startup_failure` with **zero jobs, no log, and
`referenced_workflows: []`** in the runs API. That last field is the tell: the
called workflow was never resolved, so this is not a build failure and not a
`workflow_call` input mismatch. The Actions policy refused the reference.

`hyperpolymath/standards` is a **rename** of `metadatastician/standards` (same
`repo_id`; `api.github.com/repos/hyperpolymath/standards` answers with
`full_name: metadatastician/standards` after a 301). Allowlist patterns in
`rhodium-standard-repositories/actions-allowlist/allowed-actions.json` list
`hyperpolymath/*` and do not list `metadatastician/*`, and the check is made
against the **canonical** name. So:

* `uses: hyperpolymath/standards/…` — refused (resolves to `metadatastician/…`);
* `uses: metadatastician/standards/…` — refused (no pattern covers it).

Both spellings are dead, which is why re-pointing the wrappers (the obvious
first fix, and the one this repo already tried) changed nothing.

Reproduction, no admin permission needed:

```sh
scripts/ci/triage-startup-failure.sh          # in hyperpolymath/panic-attack
# -> hyperpolymath/standards is now metadatastician/standards — allowlist
#    patterns match the repository's canonical name, so a `uses:` written with
#    the old owner is refused at startup (signature: startup_failure with
#    referenced_workflows: []).
```

## Two changes, in this order

**1. Canon: cover the canonical owner.** In
`rhodium-standard-repositories/actions-allowlist/allowed-actions.json`, add
`metadatastician/*` alongside `hyperpolymath/*`. Keep both while the rename is
in flight: callers are split across the two spellings and there is no way for a
caller to know which one its policy snapshot expects.

**2. Settings: apply the posture, do not hand-edit one pattern.** Per the
`actions-allowlist` README the default RSR posture is `allowed_actions: all`
with `sha_pinning_required: true`; `selected` is for release/signing repos.
Apply the canonical posture through the applier rather than patching a single
pattern into a drifting `selected` list:

```sh
ACTIONS_POSTURE=all scripts/set-allowed-actions.sh <org>/<repo>
```

If the org deliberately keeps `selected` for these repositories, then
`patterns_allowed` must include, at minimum:

```
metadatastician/*        # the canonical name of the standards repo (reusable workflows)
hyperpolymath/*          # legacy spelling, still referenced by callers
Swatinem/*  dtolnay/*  peter-evans/*  softprops/*
```

Note `dtolnay/rust-toolchain` is in live use across the estate and is **not** in
the canon file at the time of writing; a `selected` posture that omits it breaks
every Rust repository's setup step. Reconcile the canon with what the estate
actually calls, or move to `all`.

## Acceptance tests (please include these, not just the diff)

1. A canary repo whose workflow is `uses: metadatastician/standards/.github/workflows/rust-ci-reusable.yml@<sha>`
   produces a run with `jobs: [...]` — not `startup_failure`, and not
   `referenced_workflows: []`.
2. The same canary with the `hyperpolymath/…` spelling also starts (the rename
   must not create a cliff for callers that have not migrated).
3. `scripts/check-allowed-actions.sh` reports no gap for a workflow that
   references the standards repository under either owner.
4. A regression test in the canon's CI that fails when a repository referenced
   by any estate workflow has been renamed and its canonical owner is not in
   `patterns_allowed`. This is the class of failure — a *renamed* upstream, not
   a missing pattern — that cost four hours of unreadable red.

## What the caller repository is doing meanwhile

`hyperpolymath/panic-attack` has:

* pinned every `uses:` to a 40-hex commit (tag pins are refused under
  `sha_pinning_required`);
* added `scripts/ci/triage-startup-failure.sh`, run in `ci-integrity.yml`, which
  names the renamed upstream instead of leaving `startup_failure` unexplained;
* kept its six wrappers pointing at the reusable workflows rather than
  re-implementing them locally, so the gates come back the moment the policy
  permits them — six workflows are queued behind this change.
