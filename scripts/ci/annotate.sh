#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# annotate.sh — run a command and turn its failures into GitHub ANNOTATIONS.
#
# WHY: a failed step whose only output is in a log download is a failure half the
# world cannot read — offline contributors, anyone with a restricted network, and
# any automation that reads the checks API (the log endpoint is a different host
# from the API and is frequently unavailable). Annotations are served by the API,
# so they are the durable record of *why* a job failed.
#
# Usage: scripts/ci/annotate.sh <label> -- <command> [args...]
#
# Emits at most 20 `::error::` annotations (GitHub's practical limit before they
# are truncated) and always re-raises the command's exit status.
set -uo pipefail

label="${1:?usage: annotate.sh <label> -- <command> [args...]}"
shift
[ "${1:-}" = "--" ] && shift

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"

if [ "$status" -ne 0 ]; then
  echo "::error::${label} failed (exit ${status})"
  # Prefer lines that name a file and position or a compiler error, then fall
  # back to fenced output so the annotation is never empty.
  {
    grep -nE '^(error|warning)(\[[A-Za-z0-9-]+\])?:' "$log" \
      | head -10 \
      | sed "s|^|::error::${label}: |"
    grep -nE '^ *--> ' "$log" | head -5 | sed "s|^|::error::${label} at |"
    grep -nE '^Diff in ' "$log" | head -20 | sed "s|^|::error::rustfmt |"
  } || true
  echo "::group::${label}: tail of output"
  tail -60 "$log"
  echo "::endgroup::"
fi

exit "$status"
