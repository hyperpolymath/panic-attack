#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# annotate.sh — run a command and turn its failures into GitHub ANNOTATIONS.
#
# WHY: a failed step whose only output is in a log download is a failure half the
# world cannot read — offline contributors, anyone with a restricted network, and
# any automation that reads the checks API (the log endpoint is a different host
# from the API and is frequently unreachable). Annotations are served by the API,
# so they are the durable record of *why* a job failed.
#
# TWO BUGS THIS SCRIPT EXISTS TO NOT HAVE
#   1. `CARGO_TERM_COLOR=always` (set for readable logs) means every line starts
#      with an ANSI escape, so `grep '^error'` matches nothing and the annotation
#      set is empty — a gate that reports "failed" with no reason. Output is
#      stripped before matching.
#   2. `rustfmt --check` prints only a `Diff in <file>:<line>:` header; the lines
#      that actually need changing are the `-`/`+` lines below it. Annotating the
#      header alone forces the reader back to the log, which is (1).
#
# Usage: scripts/ci/annotate.sh <label> -- <command> [args...]
#
# Emits at most 20 `::error::` annotations and always re-raises the exit status.
set -uo pipefail

label="${1:?usage: annotate.sh <label> -- <command> [args...]}"
shift
[ "${1:-}" = "--" ] && shift

log="$(mktemp)"
plain="$(mktemp)"
trap 'rm -f "$log" "$plain"' EXIT

"$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"

if [ "$status" -ne 0 ]; then
  echo "::error::${label} failed (exit ${status})"

  # Colour-stripped copy, used for every match below.
  sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "$log" > "$plain"

  # rustfmt: one annotation per changed line, with the real file and line.
  # rustfmt prints absolute paths; GitHub attaches a file annotation only to a
  # repository-relative one.
  if [ -n "${GITHUB_WORKSPACE:-}" ]; then
    sed -i "s|${GITHUB_WORKSPACE}/||g" "$plain"
  fi

  awk '
    /^Diff in / {
      hdr = $0
      sub(/^Diff in /, "", hdr)
      sub(/:$/, "", hdr)
      idx = match(hdr, /:[0-9]+$/)
      if (idx > 0) {
        file = substr(hdr, 1, idx - 1)
        lineno = substr(hdr, idx + 1)
      }
      next
    }
    /^[-+][^-+]/ {
      change = $0
      gsub(/%/, "%25", change)
      gsub(/\r/, "%0D", change)
      printf "::error file=%s,line=%s::rustfmt: %s\n", file, lineno, change
      next
    }
  ' "$plain" | head -20

  # Compiler / cargo diagnostics: the message plus the first position line.
  awk '
    /^[[:space:]]*(error|warning)(\[[A-Za-z0-9_-]+\])?:/ {
      msg = $0
      sub(/^[[:space:]]+/, "", msg)
      pending = 1
      print "::error::" msg
      next
    }
    # "... requires rustc 1.90" tells you what to raise the MSRV to, or which
    # dependency to pin back. It is the whole answer and it is on its own line.
    match($0, /requires rustc [0-9]/) {
      msg = $0
      sub(/^[[:space:]]+/, "", msg)
      print "::error::" msg
    }
    pending && /^[[:space:]]*--> / {
      pos = $0
      sub(/^[[:space:]]*--> /, "", pos)
      print "::error::  at " pos
      pending = 0
    }
  ' "$plain" | head -20

  echo "::group::${label}: tail of output"
  tail -60 "$plain"
  echo "::endgroup::"
fi

exit "$status"
