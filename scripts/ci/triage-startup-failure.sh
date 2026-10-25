#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# triage-startup-failure.sh — explain a run that never started.
#
# A `startup_failure` is the least legible thing GitHub Actions produces: the run
# exists, `conclusion: startup_failure`, `jobs: []`, no log, and — crucially —
# `referenced_workflows: []` even when the workflow's only job is `uses:` a
# reusable workflow from another repository. Nothing in the API says why.
#
# There are five causes, and they are distinguishable with the files plus a
# read-only API call:
#
#   1. a `uses:` that is not a 40-hex commit, under `sha_pinning_required`;
#   2. a `uses:` whose repository is NOT the one the workflow names — i.e. the
#      repo was renamed (or transferred) and the allowlist patterns match the
#      *canonical* owner, not the spelling in the file;
#   3. a reusable workflow pinned to a commit that no longer exists upstream;
#   4. a workflow file that does not parse as a workflow (GitHub's parser is
#      stricter than YAML: duplicate job keys, `on:` shapes, unknown keys);
#   5. THIS REPOSITORY's allowed-actions policy refusing a non-verified
#      cross-repository `uses:`. Under `allowed_actions: selected` with
#      `verified_allowed`, GitHub-owned and marketplace-verified actions pass and
#      a `uses: some-org/some-repo/...` does not — so checkout, cache and
#      dtolnay/rust-toolchain work while every call into the estate's own
#      reusable workflows dies at startup. The signature is exactly the one above
#      (zero jobs, `referenced_workflows: []`), and the discriminator is that
#      sibling repositories calling the SAME reusable at the SAME pin succeed.
#      Only a repository admin can change it (GET /actions/permissions is 403 for
#      an ordinary token), which is why this script reports rather than fixes.

# Set TRIAGE_SIBLINGS to a space-separated list of repositories that use the same
# reusable workflows, to have the script state the discriminator explicitly:
#   TRIAGE_SIBLINGS="hyperpolymath/hypatia hyperpolymath/verisimdb"
#
# This script checks 1–3 against the live GitHub API (read-only, no admin
# permission needed: public repository metadata is enough) and leaves 4 to
# `ci-integrity.yml`, which parses every workflow with PyYAML.
#
# Usage:
#   scripts/ci/triage-startup-failure.sh             # exit 1 on any finding
#   scripts/ci/triage-startup-failure.sh --report    # exit 0, emit ::warning::
#
# Environment:
#   GITHUB_TOKEN  optional; raises the anonymous API rate limit and lets the
#                 script see private repositories. Never required.

set -euo pipefail

REPORT_ONLY=0
if [ "${1:-}" = "--report" ]; then
    REPORT_ONLY=1
fi

cd "$(dirname "$0")/../.."

WORKFLOWS_DIR=".github/workflows"
findings=0

emit() {
    # $1 = severity (error|warning), $2 = message
    local sev="$1" msg="$2"
    if [ "$REPORT_ONLY" -eq 1 ]; then
        sev="warning"
    fi
    echo "::${sev}::${msg}"
    echo "  ${msg}" >&2
    findings=$((findings + 1))
}

api() {
    # $1 = REST path (no leading slash)
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -sSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/$1"
    else
        curl -sSL -H "Accept: application/vnd.github+json" "https://api.github.com/$1"
    fi
}

# Map "owner/repo" => canonical "owner/repo", memoised in a temp file.
CANON_CACHE="$(mktemp)"
trap 'rm -f "$CANON_CACHE"' EXIT

canonical_name() {
    local slug="$1"
    local hit
    hit="$(awk -F'\t' -v s="$slug" '$1 == s { print $2 }' "$CANON_CACHE")"
    if [ -n "$hit" ]; then
        printf '%s' "$hit"
        return 0
    fi
    local body
    body="$(api "repos/$slug")"
    local name
    name="$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("")
    sys.exit(0)
print(d.get("full_name", "") or "")')"
    printf '%s\t%s\n' "$slug" "$name" >>"$CANON_CACHE"
    printf '%s' "$name"
}

ref_exists() {
    # $1 = owner/repo, $2 = sha
    local code
    code="$(api "repos/$1/commits/$2" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("no"); sys.exit(0)
print("yes" if d.get("sha") else "no")')"
    [ "$code" = "yes" ]
}

echo "== pinned refs =="

# Each distinct ref is checked once, however many workflows use it.
mapfile -t refs < <(
    grep -rhE '^[[:space:]]*(-[[:space:]]+)?uses:' "$WORKFLOWS_DIR"/*.yml "$WORKFLOWS_DIR"/*.yaml 2>/dev/null \
        | sed -e 's/^[[:space:]]*-*[[:space:]]*uses:[[:space:]]*//' \
        | sed -e 's/[[:space:]]*#.*$//' \
        | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' \
        | sed -e '/^$/d' \
        | sort -u
)

for ref in "${refs[@]}"; do
    case "$ref" in
        ./*) continue ;;                      # same-repository call: always allowed
        docker://*) echo "  docker: $ref (not checked)"; continue ;;
    esac

    target="${ref%@*}"
    at="$(printf '%s' "$ref" | sed -e 's/.*@//')"
    owner="$(printf '%s' "$target" | cut -d/ -f1)"
    second="$(printf '%s' "$target" | cut -d/ -f2)"
    subpath="$(printf '%s' "$target" | cut -d/ -f3-)"
    repo="$owner/$second"

    if ! printf '%s' "$at" | grep -qE '^[0-9a-f]{40}$'; then
        emit error "$ref: not pinned to a 40-hex commit — refused at startup under sha_pinning_required"
        continue
    fi

    canon="$(canonical_name "$repo")"
    if [ -z "$canon" ]; then
        emit error "$repo: repository not found (or API unreachable) for \`$ref\` — the run cannot start"
        continue
    fi
    if [ "$canon" != "$repo" ]; then
        # A rename is reported, not condemned: what matters is whether the
        # reference is permitted, and a rename only bites when the allowlist
        # pattern matches the old owner and not the new one.
        emit warning "$repo now resolves to $canon — a \`uses:\` keeps working across a rename as long as an allowlist pattern matches the canonical name; check \`patterns_allowed\` before assuming this is the cause"
        repo="$canon"
    fi

    case "$subpath" in
        .github/workflows/*)
            if ! ref_exists "$repo" "$at"; then
                emit error "$ref: reusable workflow pinned to $at, which no longer exists in $repo — the caller dies before its first job"
                continue
            fi
            # The pin exists. If runs of the calling workflow still die at
            # startup, the reference is being refused by this repository's
            # allowed-actions policy — the one cause no file can show.
            echo "  cross-repo reusable: $ref"
            echo "    if the calling workflow reports startup_failure with referenced_workflows: [], this"
            echo "    repository's allowed-actions policy is refusing it. Sibling repos calling the same"
            echo "    reusable at the same pin are the discriminator; the fix needs repository admin"
            echo "    (allowed_actions=all, or add \`$owner/*\` to patterns_allowed)."
            ;;
    esac
done

if [ -n "${TRIAGE_SIBLINGS:-}" ]; then
    echo "== discriminator: do siblings actually run this? =="
    for sib in $TRIAGE_SIBLINGS; do
        summary="$(api "repos/$sib/actions/runs?per_page=20")"
        printf '%s\n' "$summary" | python3 -c '
import json, sys, collections
try:
    d = json.load(sys.stdin)
except Exception:
    print("  (unreadable)"); sys.exit(0)
counts = collections.Counter((r.get("conclusion") or r.get("status")) for r in d.get("workflow_runs", []))
print("  " + ", ".join(f"{k}={v}" for k, v in counts.most_common()) or "  (no runs)")
' | sed "s|^|  $sib: |"
    done
    echo "  A sibling whose reusable-workflow runs SUCCEED, at the same pin, means the"
    echo "  estate allowlist is fine and the refusal is scoped to this repository."
fi

echo "== summary =="
if [ "$findings" -eq 0 ]; then
    echo "no startup-failure causes found in $WORKFLOWS_DIR"
else
    echo "$findings finding(s) — see above. Each one produces a run with zero jobs and no log."
fi

if [ "$REPORT_ONLY" -eq 1 ]; then
    exit 0
fi
[ "$findings" -eq 0 ]
