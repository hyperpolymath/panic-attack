<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# Owner action: this repository's Actions policy refuses cross-repository reusable workflows

Copy everything below the line into a session with repository-admin access (or
straight into a shell with an admin token). It names the evidence, the single
setting, and the acceptance test.

---

## The one-line ask

Set `hyperpolymath/panic-attack`'s Actions policy to the estate default posture —
`allowed_actions: all` with `sha_pinning_required: true` — or, if `selected` must
stay, add `hyperpolymath/*` and `slsa-framework/*` to `patterns_allowed`.

## Why: six workflows cannot start, and one of them is a required check

`main` requires two status checks (`gh api repos/hyperpolymath/panic-attack/rules/branches/main`):

```
required_status_checks: CodeQL          ← passes
required_status_checks: scan / gitleaks ← NEVER ARRIVES
```

`scan / gitleaks` comes from `secret-scanner.yml`, whose only job is

```yaml
uses: hyperpolymath/standards/.github/workflows/secret-scanner-reusable.yml@333b06a01db1874ffedb2de1bfabb195640927c7
```

Every run of it concludes **`startup_failure` with zero jobs, no log, and
`referenced_workflows: []`**. So the required context is missing rather than
failing, which blocks every pull request with no explanation anywhere in the UI.
The same applies to `rust-ci.yml`, `governance.yml`, `hypatia-scan.yml`,
`scorecard.yml`, `mirror.yml`, and to the `slsa-framework` generator called by
`release.yml`.

## The evidence that this is repo-scoped, not estate-wide

The estate allowlist is **not** the problem. `rhodium-standard-repositories/actions-allowlist/allowed-actions.json`
already contains `hyperpolymath/*`, and sibling repositories call the *same*
reusable workflows at the *same pin* successfully:

| repository | caller | pin | latest runs |
|---|---|---|---|
| `hyperpolymath/hypatia` | `secret-scanner.yml`, `governance.yml`, `hypatia-scan.yml` | `333b06a0…` | success |
| `hyperpolymath/verisimdb` | `secret-scanner.yml` | `84355587…` | success |
| `hyperpolymath/panic-attack` | the same files, the same `333b06a0…` | — | `startup_failure`, 0 jobs |

What differs is the per-repository policy. The failure pattern inside this repo
identifies it precisely:

* GitHub-owned actions work (`actions/checkout`, `actions/cache`,
  `actions/upload-artifact`);
* marketplace-verified actions work (`dtolnay/rust-toolchain`,
  `Swatinem/rust-cache`);
* **every non-verified cross-repository `uses:` dies at startup.**

That is the signature of `allowed_actions: selected` with `verified_allowed`
(`github_owned_allowed: true`, `verified_allowed: true`) and a `patterns_allowed`
list that does not include the estate's own organisation. `hyperpolymath/standards`
is not a marketplace-verified publisher, so nothing covers it.

You can reproduce the diagnosis in one command, without admin rights:

```sh
scripts/ci/triage-startup-failure.sh                    # as a report
TRIAGE_SIBLINGS="hyperpolymath/hypatia" scripts/ci/triage-startup-failure.sh
```

The policy itself is unreadable with a non-admin token —
`GET /repos/hyperpolymath/panic-attack/actions/permissions` returns **403** —
which is why this is an owner action rather than a pull request.

## The change

Either, using the canon tooling:

```sh
scripts/set-allowed-actions.sh hyperpolymath/panic-attack      # allowed_actions: all
```

or, if `selected` is deliberate for this repository:

```sh
gh api -X PUT repos/hyperpolymath/panic-attack/actions/permissions/selected-actions \
  -f github_owned_allowed=true \
  -f verified_allowed=true \
  -f 'patterns_allowed[]=hyperpolymath/*' \
  -f 'patterns_allowed[]=slsa-framework/*'
```

Keep `sha_pinning_required: true` either way: this repository pins every `uses:`
to a 40-hex commit already (gated by `ci-integrity.yml`), so the stronger control
costs nothing.

## Acceptance tests

1. `gh workflow run secret-scanner.yml --ref main` produces a run with `jobs: […]`
   — **not** `startup_failure`, and not `referenced_workflows: []`.
2. The check named **`scan / gitleaks`** appears on a pull request. Until it does,
   no pull request in this repository can merge, whatever else is green.
3. `hypatia-scan.yml`, `governance.yml` and `rust-ci.yml` start (they share the
   failure and the fix).
4. `scripts/ci/triage-startup-failure.sh` reports zero findings.

## What the repository has already done, so this is the only thing left

* every `uses:` pinned to a 40-hex commit with a `# <version>` comment, gated by
  `ci-integrity.yml`;
* `scripts/ci/triage-startup-failure.sh` in CI, which names this exact cause
  instead of leaving `startup_failure` unexplained;
* `verify.yml`, a build/lint/test/doc gate that depends on **nothing** outside
  this repository, so "does it compile and pass" stays answerable while the
  estate gates are dark;
* `docs/CI-CD.adoc` records the failure and its diagnosis.
