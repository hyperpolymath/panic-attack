#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# SHA-Pinning Validation -- canon rule 10: every third-party `uses:` ref names a
# full commit SHA, never a moving tag or a branch.
#
# TWO BUGS IN THE VERSION THIS REPLACES, both measured 2026-09-21 on main:
#
#   1. The fallback scan was
#          find "$SCAN_PATH" -path '*/.git/*' -prune -o \
#              -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' -print
#      `find` applies a bare action to the last test only, so -print bound to the
#      *.yaml clause alone. This repo has 53 root .yml workflows and no .yaml ones,
#      so find emitted 0 paths, the loop validated nothing, and the hook announced
#      "All workflow actions are SHA-pinned" over 26 unpinned refs. Parenthesising
#      the -o chain would have emitted 166. A scan that finds nothing must say so,
#      hence the empty-tree refusal below -- that guard is the part that keeps this
#      class of silent all-clear from coming back.
#
#   2. validate_file() whitened whole files: it complained only when a file had an
#      unpinned ref AND no pinned ref anywhere, so one `actions/checkout@<sha>`
#      excused every other action in the same workflow. Validation is per line now.
#
# SCOPE. Root .github/{workflows,actions} plus those directories in nested trees,
# minus rhodium-standard-repositories/**: that subtree is a vendored mirror of the
# RSR canon (gitlab.com/hyperpolymath/rhodium-standard-repositories), other
# repositories' workflows reproduced here as templates. Re-pinning it here fixes no
# live runner and desynchronises the mirror, so its unpinned refs are measured and
# tolerated in .machine_readable/Debtfile.a2ml (vendored-mirror-unpinned-actions)
# rather than skipped silently. The scope matches .githooks/validate-actions-lock.sh,
# the sibling hook this repo also runs in CI (.github/workflows/actions-lock-gate.yml).
set -euo pipefail
command -v yq >/dev/null 2>&1 || { echo "[validate-sha-pins] ERROR: yq not found -- required to read workflows (YAML-POLICY Y-1)" >&2; exit 1; }
SCAN_PATH="${INPUT_PATH:-.}"
STAGED_FILES="${INPUT_STAGED_FILES:-}"
VENDORED_MARK="rhodium-standard-repositories/"
ERRORS=0
SCANNED=0
SKIPPED=0

is_vendored() { case "$1" in *"${VENDORED_MARK}"*) return 0 ;; *) return 1 ;; esac; }

# Prints one `<line>:uses: <ref>` record per ref in <file> that is neither a
# full-SHA pin, a local path, nor a docker:// image (or one record naming a
# parse failure). Empty output means the file is clean. Local paths (`./`,
# `../`) are this repo's own composite actions and `docker://` refs are container
# images, not actions -- neither is modelled by actions.lock, which keys actions only.
UNPINNED_FILTER() {
  # ONE pipeline, and the first selector matches any NON-BLANK ref.
  #
  # Two defects are cured here, and the second hid the first.
  #
  # 1. The selector used to demand `[A-Za-z0-9]`, so a ref that is not
  #    alphanumeric was dropped before any later arm saw it. `gh actions-lock`
  #    REWRITE MODE emits `uses: $/.github/actions/...` (measured; it also
  #    de-pinned 24 SHAs). `$` is not alphanumeric, so that corruption was
  #    never reported and a workflow that dies at STARTUP scanned CLEAN.
  #
  # 2. The cure attempted for (1) was a SECOND grep in the same brace group:
  #    `{ grep A ... ; grep B ; } < "$file"`. Both greps share one stdin, the
  #    first reads it to EOF, and the second is handed an exhausted stream. It
  #    matched in isolation and emitted nothing in place — dead code that made
  #    the gate look fixed. Its comment claimed "zero matches tree-wide today;
  #    this arm is purely prospective", which was false: signed-push-smoke.yml
  #    carried a live `$/` ref the whole time. A second reader of one stdin is
  #    never a second chance.
  #
  # 3. (YAML-POLICY Y-1) The selector was a line grep, which saw only block
  #    style: a quoted ref (`uses: "./x"`) slipped past the local-path arm and
  #    was false-failed, a one-line flow step (`- { uses: a/b@v1 }`) was never
  #    matched at all, and `uses:` text inside a `run:` body was read as a ref.
  #    Refs now come from the YAML parser, one `<line>:uses: <ref>` record each;
  #    a file that does not parse is reported as such, never scanned clean.
  #
  # An unknown-shaped ref must be REPORTED, never skipped. The exemptions below
  # are the only way out, and each one is explicit.
  local file=$1 refs
  if ! refs=$(yq -r '.. | select(tag == "!!map") | select(has("uses")) | .uses | select(tag == "!!str") | ((line | tostring) + ":" + .)' "$file" 2>&1); then
    printf '0:uses: <unparseable YAML: %s>\n' "$(printf '%s' "$refs" | head -1)"
    return 0
  fi
  # An unclosed quote can swallow a workflow into one scalar that still parses,
  # leaving no jobs and no refs: that is a broken file, not a clean one.
  case "$file" in
    *.github/workflows/*)
      if [ "$(yq -r '.jobs | tag' "$file" 2>/dev/null)" != '!!map' ]; then
        printf '0:uses: <unparseable YAML: parses, but has no jobs: map>\n'
        return 0
      fi ;;
  esac
  [ -n "$refs" ] || return 0
  printf '%s\n' "$refs" \
    | sed -E 's/^([0-9]+):/\1:uses: /' \
    | { /usr/bin/grep -E '^[0-9]+:uses: [^[:space:]]' || true; } \
    | { /usr/bin/grep -vE '^[0-9]+:uses: [./]' || true; } \
    | { /usr/bin/grep -vE '^[0-9]+:uses: docker://' || true; } \
    | { /usr/bin/grep -vE '^[0-9]+:uses: [^[:space:]@]+@[0-9a-f]{40}$' || true; }
}

# Reports every unpinned or invalid `uses:` ref in <file> to stderr and adds
# one to ERRORS per ref.
validate_file() {
  local file="$1" rec lineno body
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    lineno="${rec%%:*}"
    body="${rec#*:}"
    body="${body#"${body%%[![:space:]]*}"}"
    echo "[validate-sha-pins] ERROR: $file:$lineno: ${body}" >&2
    case "$body" in
      *'<unparseable YAML'*)
        echo "    the file does not parse as YAML, so no ref in it was checked." >&2
        ;;
      *'uses:'*'$/'*)
        # Name the real fault. `$/...` is not an unpinned ref, it is not valid
        # `uses:` syntax at all, so the workflow dies at STARTUP and no job of
        # it ever runs. Reporting it as "unpinned" sends the reader hunting a
        # SHA that was never the problem.
        echo "    invalid ref: a '\$/'-leading ref is not valid uses: syntax and kills the" >&2
        echo "    workflow at startup. This is the gh actions-lock rewrite-mode corruption;" >&2
        echo "    a local action is written 'uses: ./.github/actions/<name>'." >&2
        ;;
      *)
        echo "    unpinned ref: canon rule 10 wants owner/repo@<40-hex> plus a '# <version>' comment," >&2
        echo "    and a matching key in .github/workflows/actions.lock" >&2
        ;;
    esac
    ERRORS=$((ERRORS + 1))
  done < <(UNPINNED_FILTER "$file")
}

if [ -n "$STAGED_FILES" ]; then
  while IFS=$'\n' read -r file; do
    [ -n "$file" ] || continue
    case "$file" in *.yml|*.yaml) ;; *) continue ;; esac
    case "$file" in *".github/workflows/"*|*".github/actions/"*) ;; *) continue ;; esac
    is_vendored "$file" && { SKIPPED=$((SKIPPED + 1)); continue; }
    [ -f "$file" ] || continue
    SCANNED=$((SCANNED + 1))
    validate_file "$file"
  done <<< "$STAGED_FILES"
else
  ALL=()
  while IFS= read -r f; do
    [ -n "$f" ] && ALL+=("$f")
  done < <(find "$SCAN_PATH" \
              -path '*/.git/*' -prune -o \
              \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
                 -o -path '*/.github/actions/*.yml'   -o -path '*/.github/actions/*.yaml' \) \
              -print 2>/dev/null | LC_ALL=C sort)
  # An empty scan is not a pass -- see bug 1 above.
  if [ "${#ALL[@]}" -eq 0 ]; then
    echo "[validate-sha-pins] ERROR: found 0 workflow files under '$SCAN_PATH'; refusing to certify a tree it never scanned" >&2
    exit 1
  fi
  for f in "${ALL[@]}"; do
    if is_vendored "$f"; then SKIPPED=$((SKIPPED + 1)); continue; fi
    SCANNED=$((SCANNED + 1))
    validate_file "$f"
  done
fi

echo "[validate-sha-pins] ${SCANNED} workflow file(s) scanned, ${SKIPPED} vendored mirror file(s) excluded, ${ERRORS} unpinned ref(s)"
if [ "$ERRORS" -gt 0 ]; then
  echo "[validate-sha-pins] FAIL: $ERRORS unpinned action ref(s)" >&2
  exit 1
fi
echo "[validate-sha-pins] OK: every third-party uses: ref in scope is pinned to a full SHA"
exit 0
