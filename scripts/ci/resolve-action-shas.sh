#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Resolve every tag/branch `uses:` ref in .github/workflows to a full commit
# SHA and write the mapping to a JSON file for scripts/ci/pin-workflow-uses.py.
#
# Needs `gh` (authenticated) and `jq`. One API call per distinct ref.
#
# Usage: scripts/ci/resolve-action-shas.sh [output.json]
#        default output: .github/workflows/action-pins.json
#
# The output is deliberately checked in next to the lockfile: it records which
# tag a pin stood for on the day it was taken, which is the only way a reviewer
# can tell an intentional bump from a silent re-point.
set -euo pipefail

OUT="${1:-.github/workflows/action-pins.json}"
command -v gh >/dev/null || { echo "resolve-action-shas: gh not found" >&2; exit 2; }
command -v jq >/dev/null || { echo "resolve-action-shas: jq not found" >&2; exit 2; }

# Every `uses:` ref, excluding comments, local actions and container images.
mapfile -t REFS < <(
  grep -hE '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/*.yml 2>/dev/null \
    | sed -E 's/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//' \
    | sed -E 's/[[:space:]]*#.*$//' \
    | grep -E '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+' \
    | sort -u
)
[ "${#REFS[@]}" -gt 0 ] || { echo "resolve-action-shas: no refs found" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo '{}' > "$tmp"

for ref in "${REFS[@]}"; do
  # Actions and reusable workflows are identified by owner/repo only: strip any
  # sub-path (`github/codeql-action/init`, or a reusable's
  # `.github/workflows/x.yml`). Keep exactly the first two segments.
  path="${ref%@*}"
  tag="${ref##*@}"
  owner="${path%%/*}"
  remainder="${path#*/}"
  repo="${remainder%%/*}"
  [ -n "$owner" ] && [ -n "$repo" ] && [ "$repo" != "$remainder" -o -n "$repo" ] || continue
  action="${owner}/${repo}"
  if [[ "$tag" =~ ^[0-9a-f]{40}$ ]]; then
    sha="$tag"
  else
    sha="$(gh api "repos/$action/commits/$tag" --jq .sha 2>/dev/null || true)"
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "resolve-action-shas: could not resolve $ref" >&2
    continue
  fi
  jq --arg key "${action}@${tag}" --arg sha "$sha" --arg tag "$tag" \
     '.[$key] = {sha: $sha, tag: $tag}' "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"
  printf '  %-62s -> %s\n' "${action}@${tag}" "$sha"
done

jq -S . "$tmp" > "$OUT"
echo "wrote $OUT ($(jq 'length' "$OUT") refs)"
