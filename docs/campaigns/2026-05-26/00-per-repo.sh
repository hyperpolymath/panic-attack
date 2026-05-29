#!/usr/bin/env bash
# Per-repo assail loop with timeout. No single repo can stall the campaign.
set -uo pipefail

ESTATE="${ESTATE:-/home/hyperpolymath/developer/repos}"
CAMP="${CAMP:-/tmp/panic-attack-campaign-2026-05-26}"
BIN="${BIN:-$ESTATE/panic-attack/target/release/panic-attack}"
TIMEOUT="${TIMEOUT:-90}"
PER_REPO="$CAMP/per-repo"
LOG="$CAMP/00-per-repo.log"
DONE_FILE="$CAMP/00-per-repo-done.txt"
SKIPPED_FILE="$CAMP/00-per-repo-skipped.txt"

mkdir -p "$PER_REPO"
: > "$LOG"
: > "$DONE_FILE"
: > "$SKIPPED_FILE"

echo "=== per-repo assail $(date -u --iso=seconds) timeout=${TIMEOUT}s ===" | tee -a "$LOG"

# Build repo list: top-level dirs with .git/ as a directory
REPOS=()
for d in "$ESTATE"/*; do
  [ -d "$d/.git" ] || continue
  REPOS+=("$d")
done
TOTAL=${#REPOS[@]}
echo "estate: $TOTAL repos" | tee -a "$LOG"

I=0
for repo in "${REPOS[@]}"; do
  I=$((I + 1))
  name=$(basename "$repo")
  # Skip the canonical tool repo (we don't audit ourselves here)
  if [ "$name" = "panic-attack" ]; then
    echo "[$I/$TOTAL] $name — SKIP (canonical tool)" | tee -a "$LOG"
    continue
  fi
  out="$PER_REPO/${name}.json"
  start=$SECONDS
  if timeout "${TIMEOUT}s" "$BIN" assail "$repo" --headless --output "$out" >/dev/null 2>&1; then
    dur=$((SECONDS - start))
    findings=$(jq '.weak_points | length' "$out" 2>/dev/null || echo "?")
    crit=$(jq '[.weak_points[] | select(.severity == "Critical")] | length' "$out" 2>/dev/null || echo "?")
    high=$(jq '[.weak_points[] | select(.severity == "High")] | length' "$out" 2>/dev/null || echo "?")
    echo "[$I/$TOTAL] $name ✓ ${dur}s findings=$findings crit=$crit high=$high" | tee -a "$LOG"
    echo "$name" >> "$DONE_FILE"
  else
    dur=$((SECONDS - start))
    echo "[$I/$TOTAL] $name ✗ TIMEOUT(${dur}s)" | tee -a "$LOG"
    echo "$name" >> "$SKIPPED_FILE"
    rm -f "$out"
  fi
done

echo "=== pass complete $(date -u --iso=seconds) ===" | tee -a "$LOG"
echo "done: $(wc -l < "$DONE_FILE")" | tee -a "$LOG"
echo "skipped: $(wc -l < "$SKIPPED_FILE")" | tee -a "$LOG"
