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
# There are four causes, and they are distinguishable from the files alone:
#
#   1. a `uses:` that is not a 40-hex commit, under `sha_pinning_required`;
#   2. a `uses:` whose repository is NOT the one the workflow names — i.e. the
#      repo was renamed (or transferred) and the allowlist patterns match the
#      *canonical* owner, not the spelling in the file;
#   3. a reusable workflow pinned to a commit that no longer exists upstream;
#   4. a workflow file that does not parse as a workflow (GitHub's parser is
#      stricter than YAML: duplicate job keys, `on:` shapes, unknown keys).
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
        emit error "$repo is now $canon — allowlist patterns match the repository's canonical name, so a \`uses:\` written with the old owner is refused at startup (signature: \`startup_failure\` with \`referenced_workflows: []\`). Write \`$canon\` here, and only after the canonical owner is in \`patterns_allowed\`."
        repo="$canon"
    fi

    case "$subpath" in
        .github/workflows/*)
            if ! ref_exists "$repo" "$at"; then
                emit error "$ref: reusable workflow pinned to $at, which no longer exists in $repo — the caller dies before its first job"
            fi
            ;;
    esac
done

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
