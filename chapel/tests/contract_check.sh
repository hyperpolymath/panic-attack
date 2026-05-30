#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# contract_check.sh — assert the panic-attack CLI contract surface that the
# Chapel mass-panic harness depends on remains stable.
#
# Reads chapel/tests/expected_contract.json (the fixture) and compares against
# the live `panic-attack describe-contract` JSON. Any divergence (missing mode,
# missing flag, drifted report_schema_version) fails the build.
#
# Usage:
#   ./chapel/tests/contract_check.sh [path-to-panic-attack-binary]
# Default: ./target/release/panic-attack
#
# Exit codes: 0 ok, 1 contract drift, 2 fixture/tool problem.

set -euo pipefail

BIN="${1:-./target/release/panic-attack}"
FIXTURE="$(cd "$(dirname "$0")" && pwd)/expected_contract.json"

if [[ ! -x "$BIN" ]]; then
  echo "contract_check: ERROR: panic-attack binary not found or not executable: $BIN" >&2
  exit 2
fi
if [[ ! -r "$FIXTURE" ]]; then
  echo "contract_check: ERROR: fixture not readable: $FIXTURE" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "contract_check: ERROR: jq is required" >&2
  exit 2
fi

CONTRACT="$("$BIN" describe-contract)"

errors=0

# Schema-version pin
expected_schema=$(jq -r '.report_schema_version' "$FIXTURE")
actual_schema=$(jq -r '.report_schema_version' <<<"$CONTRACT")
if [[ "$expected_schema" != "$actual_schema" ]]; then
  echo "contract_check: FAIL [schema] expected '$expected_schema', got '$actual_schema'" >&2
  errors=$((errors + 1))
fi

# Required modes
while IFS= read -r mode; do
  if ! jq -e --arg m "$mode" '.modes[$m]' <<<"$CONTRACT" >/dev/null; then
    echo "contract_check: FAIL [mode] required mode '$mode' missing from describe-contract output" >&2
    errors=$((errors + 1))
  fi
done < <(jq -r '.required_modes[]' "$FIXTURE")

# Required global flags
while IFS= read -r flag; do
  if ! jq -e --arg f "$flag" '.global_flags | index($f)' <<<"$CONTRACT" >/dev/null; then
    echo "contract_check: FAIL [global] required global flag '$flag' missing" >&2
    errors=$((errors + 1))
  fi
done < <(jq -r '.required_global_flags[]' "$FIXTURE")

# Required flags per mode
while IFS= read -r mode; do
  while IFS= read -r flag; do
    if ! jq -e --arg m "$mode" --arg f "$flag" '.modes[$m].flags | index($f)' <<<"$CONTRACT" >/dev/null; then
      echo "contract_check: FAIL [flag] mode '$mode' missing required flag '$flag'" >&2
      errors=$((errors + 1))
    fi
  done < <(jq -r --arg m "$mode" '.required_flags_per_mode[$m][]' "$FIXTURE")
done < <(jq -r '.required_flags_per_mode | keys[]' "$FIXTURE")

if [[ $errors -eq 0 ]]; then
  echo "contract_check: PASS — $(jq -r '.required_modes | length' "$FIXTURE") modes, $(jq -r '.required_global_flags | length' "$FIXTURE") global flags, $(jq -r '[.required_flags_per_mode[][]] | length' "$FIXTURE") per-mode flags verified."
  exit 0
fi

echo "contract_check: $errors drift(s) detected. Run \`$BIN describe-contract\` and compare to $FIXTURE." >&2
exit 1
