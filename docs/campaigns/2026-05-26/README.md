<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
-->

# Campaign 2026-05-26 — driver scripts

These are the driver scripts used to run the 2026-05-26 estate sweep. They're filed alongside the human + machine campaign reports so the campaign is reproducible. See [`../2026-05-26.md`](../2026-05-26.md) for the report.

## Scripts

| Script | Purpose |
|---|---|
| `00-per-repo.sh` | Iterates top-level dirs with `.git/` and runs `panic-attack assail --headless` against each with a 90s timeout. Writes per-repo JSON to `/tmp/panic-attack-campaign-<date>/per-repo/<repo>.json`. Pivot away from `assemblyline` so no single slow repo can stall the whole batch. |
| `00b-nested.sh` | Same scan loop but for nested-repo containers (`a2ml`, `awesome-projects`, `idaptik`, `isers`, `julia-libraries`, `k9`). Output filenames use `parent__child.json` to avoid collisions. |
| `01-triage.ts` | Deno script that reads per-repo JSONs and classifies into autofix / issue / proof-draft / skip buckets. Writes `02-plan.json`. |
| `file-ffi-pr-v2.sh` | Per-repo classification PR generator. Accepts `REPO_NAME`, `PREFIX_JSON` (JSON array of path prefixes), `SHORT_RATIONALE`, optional `CLASSIFICATION` (default `legitimate-ffi`). Builds the `audits/assail-classifications.a2ml` + audit doc, commits with the GPG override flags, pushes, opens a PR. **v2** uses `--argjson` + `any()` for the prefix filter (the v1 chained-OR form was broken under jq operator precedence). |

## Known gotchas

1. `file-ffi-pr-v2.sh` does `cat > audits/assail-classifications.a2ml` without checking whether the file already exists on `origin/main`. If it does, the existing entries get overwritten. **Always `git show origin/main:audits/assail-classifications.a2ml` before running the script**, and if entries exist, edit the script to preserve them.
2. Some repos are forks on GitHub with issues disabled (`linguist`, `rescript`, `HOL`) — Track A PRs land, but Track C tracking issues can't be filed.
3. Some repos are archived (`polystack`) or deleted (`hyperpolymath-archive`); skip them.
4. valence-shell-style local-only commits on `main` need branching from `origin/main` (not local `main`) to preserve them.

## Re-running

```sh
# Phase 1: per-repo scan (~10 min)
bash 00-per-repo.sh && bash 00b-nested.sh

# Phase 1b: triage
deno run --allow-read --allow-write 01-triage.ts

# Phase 2..N: per-repo PRs (one invocation per repo)
BRANCH=panic-fix/PA001-PA007-ffi-legitimate \
  bash file-ffi-pr-v2.sh \
    <repo-name> \
    '["src/<prefix>/", "ffi/<prefix>/"]' \
    "Rationale text..." \
    "legitimate-ffi"
```

The output JSONs and triage plan are NOT committed to the repo (they're ephemeral, scan-time-sensitive). See [`../2026-05-26.md`](../2026-05-26.md) for the persistent campaign record.
