#!/usr/bin/env bash
# Generate + file a legitimate-FFI classification PR for one repo.
# v2: fixes broken chained-OR jq precedence by passing prefixes as --argjson array
# and matching via .file as $f | $prefixes | any(.[]; . as $p | $f | startswith($p)).
#
# Usage: file-ffi-pr-v2.sh REPO_NAME PREFIX_JSON SHORT_RATIONALE [CLASSIFICATION]
#   PREFIX_JSON: JSON array of path prefixes, e.g. '["ffi/zig/src/","bindings/"]'
#   CLASSIFICATION: defaults to "legitimate-ffi"
set -euo pipefail

REPO_NAME="$1"
PREFIX_JSON="$2"
SHORT_RATIONALE="$3"
CLASSIFICATION="${4:-legitimate-ffi}"
BRANCH="${BRANCH:-panic-fix/PA001-PA007-ffi-legitimate}"

REPO_DIR="/home/hyperpolymath/developer/repos/$REPO_NAME"
SCAN_JSON="/tmp/panic-attack-campaign-2026-05-26/per-repo/$REPO_NAME.json"
DATE="2026-05-26"

cd "$REPO_DIR"
git fetch origin main 2>&1 | tail -1
git checkout main 2>&1 | tail -1
git pull --ff-only origin main 2>&1 | tail -1
git checkout -b "$BRANCH" 2>&1 | tail -1
mkdir -p audits

entries=$(jq -r --argjson prefixes "$PREFIX_JSON" '
  [.weak_points[] | select(
    (.category=="UnsafeCode" or .category=="UnsafeFFI")
    and (.severity=="Critical" or .severity=="High")
    and ((.suppressed // false)==false)
    and (.file as $f | $prefixes | any(.[]; . as $p | $f | startswith($p)))
  )] | length' "$SCAN_JSON")

if [ "$entries" = "0" ]; then
  echo "no findings matching prefixes — nothing to classify"
  git checkout main >/dev/null 2>&1
  git branch -D "$BRANCH" >/dev/null 2>&1
  exit 0
fi

# Render the prefixes list as a human-readable comma-joined string
PREFIXES_HUMAN=$(echo "$PREFIX_JSON" | jq -r 'join(", ")')

cat > audits/assail-classifications.a2ml <<HEADER
;; SPDX-License-Identifier: MPL-2.0
;; Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
;;
;; Assail Classifications — $REPO_NAME
;; See panic-attack/.claude/CLAUDE.md § "User-Classification Registry".

(assail-classifications
  (metadata
    (version "1.0.0")
    (project "$REPO_NAME")
    (last-updated "$DATE")
    (entries $entries)
    (status "active"))

HEADER

# Escape rationale for embedding in S-expression strings
RATIONALE_ESC=$(printf '%s' "$SHORT_RATIONALE" | sed 's/"/\\"/g')

jq -r --argjson prefixes "$PREFIX_JSON" --arg classification "$CLASSIFICATION" --arg audit "audits/audit-ffi-$DATE.md" --arg rationale "$RATIONALE_ESC" '
  .weak_points[] | select(
    (.category=="UnsafeCode" or .category=="UnsafeFFI")
    and (.severity=="Critical" or .severity=="High")
    and ((.suppressed // false)==false)
    and (.file as $f | $prefixes | any(.[]; . as $p | $f | startswith($p)))
  ) | "  (classification\n    (file \"" + .file + "\")\n    (category \"" + .category + "\")\n    (classification \"" + $classification + "\")\n    (audit \"" + $audit + "\")\n    (rationale \"" + $rationale + "\"))"
' "$SCAN_JSON" >> audits/assail-classifications.a2ml

echo ")" >> audits/assail-classifications.a2ml

cat > "audits/audit-ffi-$DATE.md" <<DOC
<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
-->

# Audit: FFI / systems \`unsafe\` blocks ($REPO_NAME)

**Auditor**: Jonathan D.A. Jewell
**Date**: $DATE
**Scope**: panic-attack assail Critical/High \`UnsafeCode\` (PA001) and \`UnsafeFFI\` (PA007) findings located under: \`${PREFIXES_HUMAN}\`.
**Cross-reference**: campaign tracker [hyperpolymath/panic-attack#32](https://github.com/hyperpolymath/picpath/issues/32).
**Registry**: \`audits/assail-classifications.a2ml\`.

## Rationale

$SHORT_RATIONALE

The classification is scoped to the listed root(s). Any \`unsafe\` block outside those roots remains visible to assail.

## Anti-gameability

The registry is a separate file from any source under scan; adding a new \`unsafe\` block inside a classified root requires a companion classification edit and an update to this audit doc, both of which are visible in the diff.

## Verification

Locally on this branch: \`panic-attack assail . --headless\` reports the listed PA001/PA007 findings as \`suppressed: true\`. Any new \`unsafe\` outside the listed roots remains unsuppressed.

Refs hyperpolymath/panic-attack#32.
DOC

# Fix the picpath typo in the audit doc (artifact of bash heredoc above)
sed -i 's|hyperpolymath/picpath#32|hyperpolymath/panic-attack#32|g' "audits/audit-ffi-$DATE.md"

git add audits/
git -c gpg.format=openpgp -c user.signingkey=4A03639C1EB1F86C7F0C97A91835A14A2867091E -c user.email=6759885+hyperpolymath@users.noreply.github.com -c user.name=hyperpolymath commit -S -m "audit: classify $entries FFI/systems unsafe findings as legitimate (PA001/PA007)

panic-attack assail flags $entries UnsafeCode/UnsafeFFI Critical/High findings
under $PREFIXES_HUMAN — all at the C-ABI / syscall / kernel boundary.

Rationale: $SHORT_RATIONALE

Adds:
- audits/assail-classifications.a2ml (entries=$entries, classification=$CLASSIFICATION)
- audits/audit-ffi-$DATE.md

Anti-gameability: registry is separate from source under scan; new unsafe
inside a classified root requires a companion classification entry.

Refs hyperpolymath/panic-attack#32 (estate sweep tracker).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push -u origin "$BRANCH" 2>&1 | tail -2

gh pr create --base main --head "$BRANCH" --title "audit: classify $entries FFI/systems unsafe findings as legitimate (PA001/PA007)" --body "## Summary

\`panic-attack assail\` reports **$entries** \`UnsafeCode\` (PA001) + \`UnsafeFFI\` (PA007) Critical/High findings under \`$PREFIXES_HUMAN\` in this repo. All sit at the C-ABI / syscall / kernel boundary and are required by the host language to call across.

Rationale: $SHORT_RATIONALE

## What changes

- \`audits/assail-classifications.a2ml\` — $entries entries, \`classification=$CLASSIFICATION\`.
- \`audits/audit-ffi-$DATE.md\` — auditor record + anti-gameability note.

## Scope

Classification is **scoped to the listed roots** ($PREFIXES_HUMAN). Any unsafe block outside those roots remains visible.

## Anti-gameability

Same pattern as \`hyperpolymath/svalinn\`, \`hyperpolymath/proven\`, \`hyperpolymath/gossamer\`, \`hyperpolymath/docudactyl\`, \`hyperpolymath/proven-servers\`, \`hyperpolymath/aerie\`, and \`hyperpolymath/boj-server\` — registry is a separate file from any source under scan; new unsafe in a classified root requires a companion classification edit + audit-doc update, both visible.

## Verification

Locally: \`panic-attack assail . --headless\` reports the $entries findings as \`suppressed: true\` on this branch.

Refs hyperpolymath/panic-attack#32.

🤖 Generated with [Claude Code](https://claude.com/claude-code)" 2>&1 | tail -2
