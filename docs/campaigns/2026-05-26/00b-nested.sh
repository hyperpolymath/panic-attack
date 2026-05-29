#!/usr/bin/env bash
# Pass 1b: per-repo assail loop for NESTED sub-repos and peer locations
# Picks up everything the top-level walker missed.
set -uo pipefail

CAMP="${CAMP:-/tmp/panic-attack-campaign-2026-05-26}"
BIN="${BIN:-/home/hyperpolymath/developer/repos/panic-attack/target/release/panic-attack}"
TIMEOUT="${TIMEOUT:-90}"
PER_REPO="$CAMP/per-repo"
LOG="$CAMP/00b-nested.log"
DONE_FILE="$CAMP/00b-nested-done.txt"
SKIPPED_FILE="$CAMP/00b-nested-skipped.txt"

mkdir -p "$PER_REPO"
: > "$LOG"
: > "$DONE_FILE"
: > "$SKIPPED_FILE"

echo "=== nested-repo assail $(date -u --iso=seconds) timeout=${TIMEOUT}s ===" | tee -a "$LOG"

# Container dirs: scan their direct children that have .git/
CONTAINERS=(
  /home/hyperpolymath/developer/repos/a2ml
  /home/hyperpolymath/developer/repos/awesome-projects
  /home/hyperpolymath/developer/repos/idaptik
  /home/hyperpolymath/developer/repos/isers
  /home/hyperpolymath/developer/repos/julia-libraries
  /home/hyperpolymath/developer/repos/k9
)
# Peer locations: scan top-level + 1 level deep
PEERS=(
  /home/hyperpolymath/typed-wasm-final
  /home/hyperpolymath/ephapax-fix
)

REPOS=()
for parent in "${CONTAINERS[@]}"; do
  for d in "$parent"/*; do
    [ -d "$d/.git" ] && REPOS+=("$d")
  done
done
for peer in "${PEERS[@]}"; do
  [ -d "$peer/.git" ] && REPOS+=("$peer")
  if [ -d "$peer" ]; then
    for d in "$peer"/*; do
      [ -d "$d/.git" ] && REPOS+=("$d")
    done
  fi
done

TOTAL=${#REPOS[@]}
echo "nested + peers: $TOTAL repos" | tee -a "$LOG"

I=0
for repo in "${REPOS[@]}"; do
  I=$((I + 1))
  # Use parent/child slug to avoid name collisions
  parent=$(basename "$(dirname "$repo")")
  child=$(basename "$repo")
  name="${parent}__${child}"
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
    echo "[$I/$TOTAL] $name ✗ TIMEOUT/EARLY-EXIT(${dur}s)" | tee -a "$LOG"
    echo "$name" >> "$SKIPPED_FILE"
    rm -f "$out"
  fi
done

echo "=== nested pass complete $(date -u --iso=seconds) ===" | tee -a "$LOG"
echo "done: $(wc -l < "$DONE_FILE")" | tee -a "$LOG"
echo "skipped: $(wc -l < "$SKIPPED_FILE")" | tee -a "$LOG"
