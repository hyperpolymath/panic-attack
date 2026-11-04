#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Isolated tree-policy controls and an explicitly injected process-status fault.
# Mock reports qualify adapter behaviour, not actual native lock coverage.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${STANDARDS_ROOT:?pinned canonical checkout required}"
: "${GH_ACTIONS_LOCK_BIN:?official binary required for the malformed-lock control}"
official_native=$GH_ACTIONS_LOCK_BIN
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/workflows" "$work/empty" "$work/repo/.github/workflows"
git -C "$work/repo" init --quiet
checker="$ROOT/scripts/ci/check-allowed-actions.sh"
transport="$ROOT/scripts/ci/actions-lock-transport.sh"
policy="$ROOT/.github/actions-allowlist.json"
checks=0
expect() {
  local expected=$1 label=$2 status=0
  shift 2
  "$@" > "$work/stdout" 2> "$work/stderr" || status=$?
  if [[ "$status" -ne "$expected" ]]; then
    cat "$work/stdout" "$work/stderr" >&2
    printf 'FAIL %s: expected %s, got %s\n' "$label" "$expected" "$status" >&2
    exit 1
  fi
  checks=$((checks + 1))
  printf 'PASS %s\n' "$label"
}
workflow() {
  jq -n --arg ref "$1" \
    '{on:{push:{}},jobs:{gate:{uses:$ref}}}' > "$work/workflows/test.yml"
}
check() { bash "$checker" "$policy" "$work/workflows"; }
canonical() { bash "$STANDARDS_ROOT/scripts/check-workflow-coordinates.sh" "$work/workflows"; }
old_pin=333b06a01db1874ffedb2de1bfabb195640927c7
current_pin=a797d308c0517d4e2d21cc7f1cb08d41f82b1a12
for name in governance hypatia-scan rust-ci; do
  workflow "metadatastician/standards/.github/workflows/$name-reusable.yml@$current_pin"
  expect 0 "exact canonical $name coordinate" check
done
for name in mirror scorecard; do
  workflow "metadatastician/standards/.github/workflows/$name-reusable.yml@$old_pin"
  expect 0 "exact canonical $name coordinate" check
done
workflow "METADATastician/STANDARDS/.github/workflows/rust-ci-reusable.yml@$current_pin"
expect 0 'owner and repository case is immaterial' check
for ref in \
  "metadatastician/standards/.github/workflows/rust-ci-reusable.yml@$old_pin" \
  "metadatastician/standards/.github/workflows/not-approved.yml@$current_pin" \
  "metadatastician/standards/.github/workflows/rust-ci-reusable.yml.extra@$current_pin" \
  "metadatastician/standards/.github/workflows/Rust-ci-reusable.yml@$current_pin" \
  "metadatastician-other/standards/.github/workflows/rust-ci-reusable.yml@$current_pin" \
  "metadatastician/standards-other/.github/workflows/rust-ci-reusable.yml@$current_pin" \
  "metadatastician/standards/.github/workflows/rust-ci-reusable.yml@main" \
  "metadatastician/standards/.github/workflows/rust-ci-reusable.yml@${current_pin}0" \
  "actions/checkout@v7.0.1" \
  '$/.github/actions/example'; do
  workflow "$ref"
  expect 1 "reject coordinate: $ref" check
done
workflow "hyperpolymath/standards/.github/workflows/rust-ci-reusable.yml@$current_pin"
expect 1 'published coordinate gate rejects the former owner despite the inherited owner-wide policy' canonical
workflow "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
jq '.github_owned_allowed = false' "$policy" > "$work/no-owned.json"
expect 1 'GitHub-owned flag is respected' bash "$checker" "$work/no-owned.json" "$work/workflows"

cat > "$work/workflows/test.yml" <<YAML
on: {push: {}}
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - {uses: "metadatastician/standards/.github/workflows/rust-ci-reusable.yml@$old_pin"}
YAML
expect 1 'quoted flow-style uses cannot hide a wrong SHA' check
cat > "$work/workflows/test.yml" <<YAML
on: {push: {}}
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - &pinned {uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"}
      - {<<: *pinned}
YAML
expect 0 'YAML aliases and merge keys are read' check
cat > "$work/workflows/test.yml" <<'YAML'
on: {push: {}}
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      # uses: unapproved/comment@main
      - run: |
          echo 'uses: unapproved/example@main'
YAML
expect 0 'quoted command and comment examples are not executable uses' check
for ref in null 42 '""' '"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n./hidden"'; do
  printf '{"jobs":{"gate":{"uses":%s}}}\n' "$ref" > "$work/workflows/test.yml"
  expect 2 "reject malformed uses value: $ref" check
done
printf 'jobs: [broken\n' > "$work/workflows/test.yml"
expect 2 'malformed YAML is unexamined' check
printf 'ordinary scalar\n' > "$work/workflows/test.yml"
expect 2 'scalar workflow is unexamined' check
expect 2 'empty input directory is not a pass' bash "$checker" "$policy" "$work/empty"
expect 2 'missing tree policy is not downloaded or assumed' bash "$checker" "$work/absent.json" "$work/workflows"
printf '%s\n%s\n' '{"github_owned_allowed":true,"patterns_allowed":[]}' '{"github_owned_allowed":true,"patterns_allowed":[]}' > "$work/stream-policy.json"
expect 2 'multiple JSON policies cannot be combined implicitly' bash "$checker" "$work/stream-policy.json" "$work/workflows"
printf '%s\n' '{"github_owned_allowed":false,"patterns_allowed":["fixture/action@*\nevil/*"]}' > "$work/newline-policy.json"
expect 2 'a newline cannot inject a second allowlist pattern' bash "$checker" "$work/newline-policy.json" "$work/workflows"

cat > "$work/mock-native" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$@" > "$MOCK_ARGS"
printf '%s|%s\n' "${GH_ACTIONS_LOCK_WORKFLOWS_DIR-unset}" "${GH_TOKEN-unset}" > "$MOCK_ENV"
cat "$MOCK_REPORT"
exit "$MOCK_STATUS"
SH
chmod +x "$work/mock-native"
export MOCK_ARGS="$work/mock-args" MOCK_ENV="$work/mock-env" MOCK_REPORT="$work/mock-report"
export GH_ACTIONS_LOCK_BIN="$work/mock-native" ACTIONS_LOCK_EVIDENCE_DIR="$work/evidence"
export GH_ACTIONS_LOCK_WORKFLOWS_DIR="$work/wrong-input" GH_TOKEN=fixture-only
printf '{"valid":true,"findings":[]}\n' > "$MOCK_REPORT"
export MOCK_STATUS=0
expect 0 'transport preserves actual success JSON' "$transport" actions-lock --verify-local --json=valid,findings
cmp "$MOCK_REPORT" "$work/stdout"
[[ "$(cat "$MOCK_ENV")" = 'unset|unset' ]] ||
  { echo 'native child retained ambient input/auth overrides' >&2; exit 1; }

cat > "$work/repo/.github/workflows/test.yml" <<'YAML'
on: {push: {}}
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - run: echo fixture
YAML
# Opaque sentinel: mocked process controls do not assert this is a native lock.
printf 'mock-only lock sentinel\n' > "$work/repo/.github/workflows/actions.lock"
before="$(sha256sum "$work/repo/.github/workflows/"*)"
helper() (
  cd "$work/repo"
  GH_BIN="$transport" bash "$STANDARDS_ROOT/scripts/update-actions-lock.sh" --verify-local
)
expect 0 'unchanged published helper accepts a successful mock protocol result' helper
for status in 2 124 127; do
  export MOCK_STATUS=$status
  expect "$status" "valid-looking JSON cannot hide native exit $status" helper
  [[ "$(cat "$ACTIONS_LOCK_EVIDENCE_DIR/native.exit")" = "$status" ]]
  cmp "$MOCK_REPORT" "$ACTIONS_LOCK_EVIDENCE_DIR/native.stdout"
  grep -F '"valid":true' "$work/stderr" >/dev/null
done
export MOCK_STATUS=0
printf 'malformed report\n' > "$MOCK_REPORT"
expect 1 'unchanged canonical parser rejects malformed success output' helper
printf '' > "$MOCK_REPORT"
expect 1 'empty success output is not accepted' helper
printf '{"valid":false,"findings":[]}\n' > "$MOCK_REPORT"
expect 1 'false validity without findings is not accepted' helper
printf '{"valid":true,"findings":[{"category":"sha-as-ref","severity":"warning","workflow":".github/workflows/test.yml","dependency":"fixture/action@0123456789012345678901234567890123456789"}]}\n' > "$MOCK_REPORT"
export MOCK_STATUS=1
expect 0 'existing canonical advisory reconciliation is preserved, not reimplemented' helper
[[ "$(sha256sum "$work/repo/.github/workflows/"*)" = "$before" ]] ||
  { echo 'mocked verification changed workflow or lock bytes' >&2; exit 1; }

rm -f "$MOCK_ARGS"
expect 2 'generator argv is forbidden in the verification transport' "$transport" actions-lock
expect 2 'unknown native option is forbidden' "$transport" actions-lock --verify-local --no-fix
expect 2 'alternate command is forbidden' "$transport" api repos/fixture
[[ ! -e "$MOCK_ARGS" ]] || { echo 'unsupported argv reached the native child' >&2; exit 1; }

export GH_ACTIONS_LOCK_BIN="$work/missing-native-binary"
expect 127 'actual missing native executable remains an infrastructure failure' helper
export GH_ACTIONS_LOCK_BIN="$official_native"
printf 'version: [malformed native lock\n' > "$work/repo/.github/workflows/actions.lock"
before="$(sha256sum "$work/repo/.github/workflows/"*)"
expect 2 'real official v0.2.0 rejects malformed native lock through the unchanged helper' helper
grep -F 'opening lockfile:' "$ACTIONS_LOCK_EVIDENCE_DIR/native.stderr" >/dev/null
[[ "$(sha256sum "$work/repo/.github/workflows/"*)" = "$before" ]] ||
  { echo 'native malformed-lock control changed input bytes' >&2; exit 1; }
printf 'CI integrity controls: %s passed; real consumer coverage is a separate gate\n' "$checks"
