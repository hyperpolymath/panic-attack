#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# check-allowed-actions.sh — make the un-squabble-able startup_failure legible.
#
# When a repo sets `allowed_actions: selected` (RSR default) and a workflow
# `uses:` an action or reusable-workflow the allowlist does not permit, the run
# dies at STARTUP with no job and no log — an opaque red you cannot "squabble"
# with (RSR-PHILOSOPHY: reach green by satisfying the gate, never admin-override).
#
# This check turns that into a concrete, satisfiable gate: it lists exactly which
# `uses:` are not covered by the canonical allowlist, so the fix is obvious
# (add the pattern, or run set-allowed-actions.sh). Needs NO API and NO admin —
# safe to run in CI, in rhodibot, or locally.
#
# Usage:  check-allowed-actions.sh [ALLOWED_ACTIONS_JSON] [WORKFLOWS_DIR]
# Exit:   0 = every `uses:` is covered; 1 = one or more gaps (printed).
set -euo pipefail
CANON="${1:-rhodium-standard-repositories/actions-allowlist/allowed-actions.json}"
WF_DIR="${2:-.github/workflows}"

if [ ! -f "$CANON" ]; then
  # fall back to the published canonical list in standards
  CANON_URL="https://raw.githubusercontent.com/hyperpolymath/standards/main/rhodium-standard-repositories/actions-allowlist/allowed-actions.json"
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  curl -fsSL "$CANON_URL" -o "$TMP" && CANON="$TMP" || { echo "!! no allowlist ($CANON)"; exit 2; }
fi

python3 - "$CANON" "$WF_DIR" <<'PY'
import json, sys, os, re, glob, fnmatch
canon = json.load(open(sys.argv[1]))
patterns = canon.get("patterns_allowed", [])
gh_owned = {"actions", "github"}  # github_owned_allowed

def owner_repo(u):
    base = u.split('@', 1)[0]
    # GitHub owner/repository names are case-insensitive.
    parts = base.lower().split('/')
    return '/'.join(parts[:2]), parts[0]

def covered(u):
    # $/ is gh actions-lock's inherently-pinned same-repo form (like ./)
    if u.startswith('./') or u.startswith('$/') or u.startswith('docker://'):
        return True
    orp, owner = owner_repo(u)
    if owner in gh_owned:                       # github-owned (actions/*, github/*)
        return True
    for p in patterns:
        base = p.split('@', 1)[0].lower()
        if base == f"{owner}/*":                # owner-wide (covers reusable workflows)
            return True
        if base == orp or fnmatch.fnmatch(orp, base):
            return True
    return False

uses = set()
for f in sorted(glob.glob(os.path.join(sys.argv[2], '*.yml')) +
                glob.glob(os.path.join(sys.argv[2], '*.yaml'))):
    for line in open(f, encoding='utf-8'):
        m = re.search(r'^\s*(?:-\s*)?uses:\s*([^\s#]+)', line)
        if m:
            uses.add(m.group(1).strip().strip('"\''))

gaps = sorted(u for u in uses if not covered(u))
for u in gaps:
    print(f"GAP  {u}   (add its owner/* or owner/repo@* pattern, or run set-allowed-actions.sh)")
print(f"checked {len(uses)} `uses:` refs across {sys.argv[2]} — {len(gaps)} not covered by the allowlist")
sys.exit(1 if gaps else 0)
PY
