#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Temporary process-status boundary for the unchanged published Standards
# verifier. Remove after standards#1394 is signed, hosted-qualified and adopted.
# This adapter does not interpret findings or implement lock reconciliation.
set -euo pipefail

if ! { [[ $# -eq 2 && $1 = actions-lock && $2 = --verify-local ]] ||
       [[ $# -eq 3 && $1 = actions-lock && $2 = --verify-local &&
          $3 = --json=valid,findings ]]; }; then
  echo 'actions-lock transport: only the two read-only verifier argv forms are permitted' >&2
  exit 2
fi
shift
: "${GH_ACTIONS_LOCK_BIN:?official binary path is required}"
: "${ACTIONS_LOCK_EVIDENCE_DIR:?raw evidence directory is required}"
mkdir -p "$ACTIONS_LOCK_EVIDENCE_DIR"
printf 'running\n' > "$ACTIONS_LOCK_EVIDENCE_DIR/native.exit"
set +e
env -u GH_ACTIONS_LOCK_WORKFLOWS_DIR -u GH_HOST -u GH_REPO \
  -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN \
  "$GH_ACTIONS_LOCK_BIN" "$@" \
  > "$ACTIONS_LOCK_EVIDENCE_DIR/native.stdout" \
  2> "$ACTIONS_LOCK_EVIDENCE_DIR/native.stderr"
status=$?
set -e
printf '%s\n' "$status" > "$ACTIONS_LOCK_EVIDENCE_DIR/native.exit"
cat "$ACTIONS_LOCK_EVIDENCE_DIR/native.stderr" >&2
case "$status" in
  0|1) cat "$ACTIONS_LOCK_EVIDENCE_DIR/native.stdout" ;;
  *)
    cat "$ACTIONS_LOCK_EVIDENCE_DIR/native.stdout" >&2
    echo "actions-lock transport: tool failed (exit $status); report not offered for reconciliation" >&2
    ;;
esac
exit "$status"
