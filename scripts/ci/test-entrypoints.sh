#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Hermetic tools: no compiler, package installer, network, or user files touched.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
just_bin=${JUST_BIN:-$(command -v just)}
just_bin=$(realpath "$just_bin")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/repo/scripts"
cp "$root/Justfile" "$root/setup.sh" "$tmp/repo/"
cp "$root/scripts/doctor.sh" "$tmp/repo/scripts/"
ln -s /bin/sh "$tmp/bin/sh"
ln -s "$(command -v head)" "$tmp/bin/head"
ln -s "$just_bin" "$tmp/bin/just"
for tool in cargo rustc git; do
    printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/$tool"
    chmod +x "$tmp/bin/$tool"
done
cd "$tmp/repo"
checks=0
expect() {
    local expected=$1 actual=0
    shift
    "$@" > "$tmp/output" 2>&1 || actual=$?
    if [[ $actual != "$expected" ]]; then
        cat "$tmp/output" >&2
        printf 'expected %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
        exit 1
    fi
    checks=$((checks + 1))
}
expect 0 "$just_bin" --list
expect 0 env PATH="$tmp/bin" "$just_bin" doctor
for tool in cargo rustc git; do
    mv "$tmp/bin/$tool" "$tmp/$tool"
    expect 1 env PATH="$tmp/bin" "$just_bin" doctor
    grep -q "\[FAIL\] $tool" "$tmp/output"
    mv "$tmp/$tool" "$tmp/bin/$tool"
    printf '#!/bin/sh\nexit 7\n' > "$tmp/bin/$tool"
    expect 1 env PATH="$tmp/bin" "$just_bin" doctor
    printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/$tool"
done
for code in 0 1 2 127; do
    printf '#!/bin/sh\nexit %s\n' "$code" > "$tmp/bin/panic-attack"
    chmod +x "$tmp/bin/panic-attack"
    expect "$code" env PATH="$tmp/bin" "$just_bin" assail
done
rm "$tmp/bin/panic-attack"
expect 127 env PATH="$tmp/bin" "$just_bin" assail
# Bootstrap must not swallow a failed doctor or emit a success report.
printf '#!/bin/sh\nprintf Linux\n' > "$tmp/bin/uname"
chmod +x "$tmp/bin/uname"
rm "$tmp/bin/cargo"
expect 1 env PATH="$tmp/bin" /bin/sh ./setup.sh
if grep -q 'Setup Complete' "$tmp/output" || [[ -e INSTALL-SECURITY-REPORT.adoc ]]; then
    echo 'bootstrap reported success after a failed diagnostic' >&2
    exit 1
fi
# Select a real setup recipe (just --list indents recipe names).
printf 'setup:\n    exit 23\n' > Justfile
expect 23 env PATH="$tmp/bin" /bin/sh ./setup.sh
printf 'entrypoint controls: %s passed\n' "$checks"
