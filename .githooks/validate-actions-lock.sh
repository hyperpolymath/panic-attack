#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Native coverage plus the published canonical reusable/local-action lock-sync
# boundary. No native YAML is generated, patched, or inferred here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
assert_clean_checkout() {
  local checkout=$1 git_state
  # Git's normal status can hide modified consumed files behind these flags.
  # NUL records keep unusual filenames from changing the flag interpretation.
  git -C "$checkout" ls-files -v -z |
    while IFS= read -r -d '' entry; do
      case "${entry:0:1}" in
        [a-z]|S)
          echo "validate-actions-lock: unsafe index flags in $checkout; source bytes are unqualified" >&2
          exit 2
          ;;
      esac
    done
  git_state="$(git -C "$checkout" status --porcelain --untracked-files=all --ignored=matching)" ||
    { echo "validate-actions-lock: cannot inspect source state in $checkout" >&2; return 2; }
  [[ -z "$git_state" ]] ||
    { echo "validate-actions-lock: tracked, untracked or ignored changes in $checkout; use an isolated clean checkout" >&2; return 2; }
}
STANDARDS_REF=087f6bff5135ce3da6f287c83752256ce4a8efc1
NATIVE_SHA256=79ec84c191667fd935a277e6fd3662cf5d3669cccc9e99998731d8f306f373b6
: "${STANDARDS_ROOT:?checkout the pinned metadatastician/standards source; see docs/CI-CD.adoc}"
: "${GH_ACTIONS_LOCK_BIN:?path to the official gh-actions-lock v0.2.0 linux-amd64 binary}"
for tool in git jq yq sha256sum diff; do
  command -v "$tool" >/dev/null || { echo "validate-actions-lock: missing $tool" >&2; exit 2; }
done
[[ "$GH_ACTIONS_LOCK_BIN" = /* && -f "$GH_ACTIONS_LOCK_BIN" && -x "$GH_ACTIONS_LOCK_BIN" ]] ||
  { echo 'validate-actions-lock: official native binary is unavailable' >&2; exit 2; }
printf '%s  %s\n' "$NATIVE_SHA256" "$GH_ACTIONS_LOCK_BIN" | sha256sum --check --status ||
  { echo 'validate-actions-lock: native binary digest mismatch' >&2; exit 2; }
STANDARDS_ROOT="$(cd "$STANDARDS_ROOT" && pwd -P)"
[[ "$(git -C "$STANDARDS_ROOT" rev-parse --show-toplevel)" = "$STANDARDS_ROOT" ]] ||
  { echo 'validate-actions-lock: Standards path must be its repository root' >&2; exit 2; }
[[ "$(git -C "$STANDARDS_ROOT" rev-parse HEAD)" = "$STANDARDS_REF" ]] ||
  { echo 'validate-actions-lock: wrong Standards source revision' >&2; exit 2; }
assert_clean_checkout "$STANDARDS_ROOT"

cd "$ROOT"
[[ "$(git rev-parse --show-toplevel)" = "$ROOT" ]] ||
  { echo 'validate-actions-lock: consumer path must be its repository root' >&2; exit 2; }
assert_clean_checkout "$ROOT"
[[ -f .github/workflows/actions.lock ]] ||
  { echo 'validate-actions-lock: missing native lock; use canonical recovery' >&2; exit 1; }
snapshot="$(mktemp -d)"
cp -a .github/workflows "$snapshot/workflows"
cleanup() {
  local status=$?
  if ! diff -qr "$snapshot/workflows" .github/workflows; then
    echo 'validate-actions-lock: verification changed workflow/lock bytes; refusing success' >&2
    status=1
  fi
  rm -rf "$snapshot"
  if [[ "$status" -eq 0 ]]; then
    echo 'validate-actions-lock: canonical native verification and lock sync passed; live GitHub admission is not established'
  fi
  exit "$status"
}
trap cleanup EXIT
export GH_ACTIONS_LOCK_BIN
export ACTIONS_LOCK_EVIDENCE_DIR="${ACTIONS_LOCK_EVIDENCE_DIR:-$snapshot/evidence}"
mkdir -p "$ACTIONS_LOCK_EVIDENCE_DIR"
printf 'not_run\n' > "$ACTIONS_LOCK_EVIDENCE_DIR/native.exit"
jq -n \
  --arg subject "$(git rev-parse HEAD)" \
  --arg tree "$(git rev-parse HEAD^{tree})" \
  --arg authority "$STANDARDS_REF" \
  --arg native_sha256 "$NATIVE_SHA256" \
  --arg run_id "${GITHUB_RUN_ID:-}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:-}" \
  '{subject_commit:$subject,subject_tree:$tree,standards_commit:$authority,
    native_version:"v0.2.0",native_sha256:$native_sha256,
    run_id:$run_id,run_attempt:$run_attempt}' \
  > "$ACTIONS_LOCK_EVIDENCE_DIR/source.json"

GH_BIN="$ROOT/scripts/ci/actions-lock-transport.sh" \
  bash "$STANDARDS_ROOT/scripts/update-actions-lock.sh" --verify-local
case "$(cat "$ACTIONS_LOCK_EVIDENCE_DIR/native.exit")" in
  0|1) ;;
  *)
    echo 'validate-actions-lock: helper returned without a completed native verifier result' >&2
    exit 1
    ;;
esac
bash "$STANDARDS_ROOT/scripts/check-lock-sync.sh" .github/workflows
