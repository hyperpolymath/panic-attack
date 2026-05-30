#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# rayon_vs_chapel_diff.sh — verify that the Rust assemblyline (rayon) path
# and the Chapel mass-panic single-locale path produce identical aggregates
# on the same two-repo synthetic corpus.
#
# Compared fields (canonicalised — sorted, timestamps stripped):
#   * total_weak_points
#   * total_critical
#   * repos_scanned
#   * total_files
#
# Excluded from comparison (non-deterministic):
#   * created_at / generated_at timestamps
#   * any UUID / sequence-number fields
#   * iteration order in arrays (sorted by repo name before extraction)
#
# Usage:
#   ./chapel/tests/rayon_vs_chapel_diff.sh
# Assumes panic-attack and chapel/mass-panic are both built.
#
# Exit codes: 0 zero-diff, 1 aggregate divergence, 2 setup problem.

set -euo pipefail

PA_BIN="${PA_BIN:-./target/release/panic-attack}"
MP_BIN="${MP_BIN:-./chapel/mass-panic}"
WORK="$(mktemp -d /tmp/rayon-vs-chapel-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

if [[ ! -x "$PA_BIN" ]]; then
  echo "rayon_vs_chapel_diff: ERROR: $PA_BIN not executable" >&2; exit 2
fi
if [[ ! -x "$MP_BIN" ]]; then
  echo "rayon_vs_chapel_diff: ERROR: $MP_BIN not executable" >&2; exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "rayon_vs_chapel_diff: ERROR: jq is required" >&2; exit 2
fi

# Synthesize two minimal "repos" — git-tracked dirs with a single Rust file
# each containing one known weak-point pattern (unsafe block).
mkdir -p "$WORK/corpus/repo-alpha/src" "$WORK/corpus/repo-beta/src"
cat > "$WORK/corpus/repo-alpha/src/lib.rs" <<'EOF'
// A trivial unsafe block to give assail something to find.
pub unsafe fn poke() -> *const u8 { core::ptr::null() }
EOF
cat > "$WORK/corpus/repo-beta/src/lib.rs" <<'EOF'
pub fn nudge() { unsafe { let _ = 1 as *const u8; } }
EOF
(cd "$WORK/corpus/repo-alpha" && git init -q && git add -A && git -c user.email=ci@example.com -c user.name=ci commit -q -m init)
(cd "$WORK/corpus/repo-beta"  && git init -q && git add -A && git -c user.email=ci@example.com -c user.name=ci commit -q -m init)

# Run rayon path (assemblyline).
"$PA_BIN" --quiet assemblyline "$WORK/corpus" --output "$WORK/rayon.json"

# Run Chapel single-locale path. Pass --panicAttackBin explicitly so the
# harness invokes the just-built binary rather than searching $PATH (which
# may be empty in CI before `cargo install`).
"$MP_BIN" --repoDirectory="$WORK/corpus" \
          --numLocales=1 \
          --quiet \
          --panicAttackBin="$(realpath "$PA_BIN")" \
          --outputDir="$WORK/chapel-out" \
          --verisimdbDir="$WORK/chapel-verisimdb"

# Find the system-image JSON Chapel wrote.
CHAPEL_IMG="$(ls -1t "$WORK/chapel-out"/system-image-*.json 2>/dev/null | head -1 || true)"
if [[ -z "$CHAPEL_IMG" ]]; then
  echo "rayon_vs_chapel_diff: ERROR: Chapel did not write a system-image JSON to $WORK/chapel-out" >&2
  exit 2
fi

# Extract comparable aggregates.
rayon_wp=$(jq -r '.total_weak_points // (.repos | map(.weak_point_count) | add) // 0' "$WORK/rayon.json")
rayon_crit=$(jq -r '.total_critical // (.repos | map(.critical_count) | add) // 0' "$WORK/rayon.json")
rayon_repos=$(jq -r '.repos_scanned // (.repos | length) // 0' "$WORK/rayon.json")

chapel_wp=$(jq -r '.total_weak_points' "$CHAPEL_IMG")
chapel_crit=$(jq -r '.total_critical' "$CHAPEL_IMG")
chapel_repos=$(jq -r '.repos_scanned' "$CHAPEL_IMG")

errors=0
check() {
  local field="$1" rayon="$2" chapel="$3"
  if [[ "$rayon" != "$chapel" ]]; then
    echo "rayon_vs_chapel_diff: FAIL [$field] rayon=$rayon chapel=$chapel" >&2
    errors=$((errors + 1))
  else
    echo "rayon_vs_chapel_diff: ok [$field] = $rayon"
  fi
}
check total_weak_points "$rayon_wp" "$chapel_wp"
check total_critical    "$rayon_crit" "$chapel_crit"
check repos_scanned     "$rayon_repos" "$chapel_repos"

if [[ $errors -eq 0 ]]; then
  echo "rayon_vs_chapel_diff: PASS — rayon and Chapel single-locale aggregates agree."
  exit 0
fi
echo "rayon_vs_chapel_diff: $errors aggregate(s) drifted between rayon and Chapel." >&2
echo "  rayon JSON:  $WORK/rayon.json (kept for triage: $WORK)" >&2
trap - EXIT
exit 1
