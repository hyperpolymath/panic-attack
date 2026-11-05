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
# This command reports source/API observations: pin shape, repository
# canonical name and whether a reusable commit can be read. Zero jobs and
# referenced_workflows: [] do not identify a cause. API reachability is not
# GitHub admission, and sibling runs are comparative evidence, not a read of
# this repository's effective Actions Settings or startup diagnostic.
#
# TRIAGE_SIBLINGS optionally lists space-separated repositories whose recent
# run conclusions will be printed without inferring a policy failure.
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
        emit error "$ref: not pinned to a 40-hex commit — source violates the immutable-ref policy"
        continue
    fi

    canon="$(canonical_name "$repo")"
    if [ -z "$canon" ]; then
        emit error "$repo: repository not found or API unreachable for \`$ref\` — source identity could not be verified"
        continue
    fi
    if [ "$canon" != "$repo" ]; then
        # A metadata redirect does not qualify executable coordinates or the
        # identity records in the consumer's generated native lock.
        emit warning "$repo now resolves to $canon — review the canonical executable coordinate and generated lock identity; this metadata redirect does not prove startup admission"
        repo="$canon"
    fi

    case "$subpath" in
        .github/workflows/*)
            if ! ref_exists "$repo" "$at"; then
                emit error "$ref: could not verify reusable commit $at in $repo — absence and API failure are not distinguished"
                continue
            fi
            echo "  cross-repo reusable: $ref"
            echo "    commit metadata is readable; this does not verify the reusable file,"
            echo "    native lock closure, effective Actions Settings or startup admission."
            echo "    use the actual platform diagnostic before attributing a zero-job failure."
            ;;
    esac
done

if [ -n "${TRIAGE_SIBLINGS:-}" ]; then
    echo "== comparative sibling run observations =="
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
    echo "  Sibling conclusions are comparative observations only; they do not establish"
    echo "  this repository's effective Actions policy or the cause of its startup failure."
fi

echo "== summary =="
if [ "$findings" -eq 0 ]; then
    echo "No source/API findings in $WORKFLOWS_DIR; live admission and startup cause remain unverified."
else
    echo "$findings source/API finding(s) — see above; platform causation is not established."
fi

if [ "$REPORT_ONLY" -eq 1 ]; then
    exit 0
fi
[ "$findings" -eq 0 ]
