#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Type-check every Idris2 module in src/abi/ and fail loudly on any error or
# escape hatch. This is the receipt for the ABI proofs listed in
# PROOF-NEEDS.adoc: until this ran, none of them had ever been checked.
#
# The files declare `module PanicAttack.ABI.<Name>` but live flat in
# src/abi/, and Idris2 requires a module's path to match its name. Moving
# them would break paths cited in legacy A2ML metadata, which agents may not
# edit, so this script stages a module-path view of the unchanged files as
# symbolic links and checks that. The bytes checked are the committed bytes.
#
# Requirements per module:
#   * `idris2 --check` succeeds under the pinned Idris2 version;
#   * the file states `%default total`;
#   * no believe_me, assert_total, assert_smaller, postulate or idris_crash
#     outside comments.
#
# Usage: scripts/ci/check-idris-abi.sh   (idris2 0.7.0 on PATH)
set -euo pipefail

IDRIS2_VERSION=0.7.0
root=$(cd "$(dirname "$0")/../.." && pwd)
abi="$root/src/abi"

version=$(idris2 --version)
[[ "$version" == "Idris 2, version $IDRIS2_VERSION"* ]] ||
    { echo "check-idris-abi: need Idris2 $IDRIS2_VERSION, got: $version" >&2; exit 2; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/PanicAttack/ABI"

failures=0
shopt -s nullglob
files=("$abi"/*.idr)
[[ ${#files[@]} -gt 0 ]] || { echo "check-idris-abi: no modules in $abi" >&2; exit 2; }

for file in "${files[@]}"; do
    name=$(basename "$file" .idr)
    declared=$(sed -n 's/^module[[:space:]]\{1,\}\([A-Za-z0-9_.]*\).*/\1/p' "$file" | head -1)
    if [[ "$declared" != "PanicAttack.ABI.$name" ]]; then
        echo "FAIL  $name: declares module '$declared', expected PanicAttack.ABI.$name"
        failures=$((failures + 1)); continue
    fi
    ln -s "$file" "$stage/PanicAttack/ABI/$name.idr"
done

for file in "${files[@]}"; do
    name=$(basename "$file" .idr)
    [[ -L "$stage/PanicAttack/ABI/$name.idr" ]] || continue
    # Code lines only: drop `--` and `|||` comment lines before searching.
    code=$(grep -vE '^[[:space:]]*(--|\|\|\|)' "$file" || true)
    if ! grep -qE '^%default[[:space:]]+total' <<<"$code"; then
        echo "FAIL  $name: missing %default total"; failures=$((failures + 1)); continue
    fi
    if hatch=$(grep -nE '\b(believe_me|assert_total|assert_smaller|postulate|idris_crash)\b' <<<"$code"); then
        echo "FAIL  $name: escape hatch: $hatch"; failures=$((failures + 1)); continue
    fi
    if out=$(cd "$stage" && idris2 --no-color --check "PanicAttack/ABI/$name.idr" 2>&1); then
        echo "PASS  $name"
    else
        echo "FAIL  $name"; printf '%s\n' "$out" | sed -n '1,40p'; failures=$((failures + 1))
    fi
done
exit "$failures"
