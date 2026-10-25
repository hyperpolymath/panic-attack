#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# Emit a test inventory: which test binaries exist and which tests they declare.
#
# WHY NOT `cargo test -- --list` ONCE: that prints every test name with no
# attribution, so a ledger entry could not say "these cells rest on these
# binaries" and a renamed binary would silently re-point every claim. One
# `--list` per binary keeps the attribution exact.
#
# Usage: scripts/proven/inventory.sh [OUT]     default: /tmp/panic-attack-tests.json
#
# Requires jq. Building the test binaries is the caller's job (`cargo test
# --no-run`); this script only lists.
set -euo pipefail

OUT="${1:-/tmp/panic-attack-tests.json}"
command -v jq >/dev/null || { echo "inventory: jq not found" >&2; exit 2; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo '{}' > "$tmp"

add() {
  local binary="$1" names
  names="$(printf '%s\n' "$2" | sed -n 's/^\(.*\): test$/\1/p' | jq -R . | jq -s .)"
  jq --arg b "$binary" --argjson n "$names" '.[$b] = $n' "$tmp" > "$tmp.new"
  mv "$tmp.new" "$tmp"
}

# Library unit tests (module::path::name).
add "panic_attack" "$(cargo test --locked --lib -- --list 2>/dev/null || true)"

# Integration test binaries, one per tests/*.rs file.
for f in tests/*.rs; do
  [ -e "$f" ] || continue
  bin="$(basename "$f" .rs)"
  case "$bin" in
    # shell-driven fixtures, not Rust test binaries
    verisimdb_e2e) continue ;;
  esac
  add "$bin" "$(cargo test --locked --test "$bin" -- --list 2>/dev/null || true)"
done

jq -S . "$tmp" > "$OUT"
total="$(jq '[.[] | length] | add // 0' "$OUT")"
bins="$(jq 'length' "$OUT")"
echo "inventory: $total test(s) in $bins binar(ies) -> $OUT"
[ "$total" -gt 0 ] || { echo "inventory: no tests found — refusing to certify an empty suite" >&2; exit 1; }
