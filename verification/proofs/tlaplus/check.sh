#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Model-check GenerationPublish.tla with every .cfg beside it.
#
# Each .cfg states its expected outcome on its second line:
#   "\* Expected: pass"                      TLC must finish with no error;
#   "\* Expected: violation of <Name> ..."   TLC must report <Name> violated.
# The expected violations are the documented mirror limit, the reader
# without a retry, and three deliberate mutants: they show the invariants
# can fail. A config that does anything else fails the run.
#
# Usage: TLA2TOOLS=/path/to/tla2tools.jar verification/proofs/tlaplus/check.sh
# The jar must be the pinned release below; its digest is checked first.
set -euo pipefail

TLA2TOOLS_VERSION=v1.7.4
TLA2TOOLS_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

jar=${TLA2TOOLS:?set TLA2TOOLS to tla2tools.jar ($TLA2TOOLS_VERSION)}
dir=$(cd "$(dirname "$0")" && pwd)
echo "$TLA2TOOLS_SHA256  $jar" | sha256sum --check --quiet

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
for cfg in "$dir"/*.cfg; do
    name=$(basename "$cfg" .cfg)
    expected=$(sed -n '2s/^\\\* Expected: //p' "$cfg")
    log="$work/$name.log"
    set +e
    java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -deadlock \
        -metadir "$work/$name.states" -config "$cfg" "$dir/GenerationPublish.tla" >"$log" 2>&1
    set -e
    states=$(grep -oE '[0-9]+ distinct states found' "$log" | tail -1 || true)
    case "$expected" in
        pass)
            if grep -q 'No error has been found' "$log"; then
                echo "PASS  $name: no error ($states)"
            else
                echo "FAIL  $name: expected no error"; sed -n '1,40p' "$log"; failures=$((failures + 1))
            fi ;;
        "violation of "*)
            prop=${expected#violation of }; prop=${prop%% *}
            if grep -qE "(Invariant|Action property) $prop is violated" "$log"; then
                echo "PASS  $name: $prop violated, as expected ($states)"
            else
                echo "FAIL  $name: expected $prop to be violated"; sed -n '1,40p' "$log"; failures=$((failures + 1))
            fi ;;
        *)
            echo "FAIL  $name: no 'Expected:' line"; failures=$((failures + 1)) ;;
    esac
done
exit "$failures"
