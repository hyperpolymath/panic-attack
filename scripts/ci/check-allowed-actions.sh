#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Offline tree policy: match the whole action/reusable coordinate and ref.
# This cannot read effective GitHub Settings or verify Marketplace publishers.
set -euo pipefail
POLICY="${1:-.github/actions-allowlist.json}"
WF_DIR="${2:-.github/workflows}"
YQ_BIN="${YQ_BIN:-yq}"
[[ -f "$POLICY" && -d "$WF_DIR" ]] ||
  { echo 'check-allowed-actions: policy file and workflow directory are required' >&2; exit 2; }
command -v "$YQ_BIN" >/dev/null && command -v jq >/dev/null ||
  { echo 'check-allowed-actions: mikefarah yq v4 and jq are required' >&2; exit 2; }
if ! jq -e -s 'length == 1 and (.[0] | type == "object" and
  (.github_owned_allowed | type == "boolean") and
  (.patterns_allowed | type == "array" and all(.[]; type == "string" and length > 0 and
    (test("\\s") | not) and (contains("\u0000") | not))))
' "$POLICY" >/dev/null; then
  echo 'check-allowed-actions: malformed tree policy' >&2
  exit 2
fi
owned="$(jq -r '.github_owned_allowed' "$POLICY")"
mapfile -t patterns < <(jq -r '.patterns_allowed[]' "$POLICY")
probe="$(printf '%s\n' '{jobs: {probe: {steps: [{uses: "Fixture/Action@0123456789012345678901234567890123456789"}]}}}' |
  "$YQ_BIN" -o=json 'explode(.)' - | jq -r '.jobs.probe.steps[0].uses')" ||
  { echo 'check-allowed-actions: YAML parser probe failed' >&2; exit 2; }
[[ "$probe" = 'Fixture/Action@0123456789012345678901234567890123456789' ]] ||
  { echo 'check-allowed-actions: YAML parser did not read the known ref' >&2; exit 2; }

covered() {
  local ref=$1 action sha owner tail repo suffix pattern base allowed_ref p_owner p_tail p_repo p_suffix
  case "$ref" in
    ./*|docker://*) return 0 ;;
    '$/'*) return 1 ;;
  esac
  [[ "$ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-fA-F]{40}$ ]] || return 1
  action="${ref%@*}"
  sha="${ref##*@}"
  sha="${sha,,}"
  case "$action" in */../*|*/./*|*/..|*/.) return 1 ;; esac
  owner="${action%%/*}"; tail="${action#*/}"; repo="${tail%%/*}"
  suffix="${tail#"$repo"}"
  action="${owner,,}/${repo,,}$suffix"
  if [[ "$owned" = true && ( "${owner,,}" = actions || "${owner,,}" = github ) ]]; then
    return 0
  fi
  for pattern in "${patterns[@]}"; do
    base="${pattern%%@*}"
    if [[ "$pattern" = *@* ]]; then
      allowed_ref="${pattern#*@}"
      if [[ "$allowed_ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
        allowed_ref="${allowed_ref,,}"
      fi
      [[ "$sha" = $allowed_ref ]] || continue
    fi
    [[ "$base" = */* ]] || continue
    p_owner="${base%%/*}"; p_tail="${base#*/}"; p_repo="${p_tail%%/*}"
    p_suffix="${p_tail#"$p_repo"}"
    base="${p_owner,,}/${p_repo,,}$p_suffix"
    [[ "$action" = $base ]] && return 0
  done
  return 1
}

scratch="$(mktemp)"
trap 'rm -f "$scratch"' EXIT
shopt -s nullglob
files=("$WF_DIR"/*.yml "$WF_DIR"/*.yaml)
[[ ${#files[@]} -gt 0 ]] ||
  { echo 'check-allowed-actions: no workflow files examined' >&2; exit 2; }
checked=0
gaps=0
for file in "${files[@]}"; do
  if ! "$YQ_BIN" -o=json 'explode(.)' "$file" > "$scratch"; then
    echo "check-allowed-actions: unparseable workflow: $file" >&2
    exit 2
  fi
  # A scalar, invalid jobs/steps node, null/non-string uses, or whitespace in
  # a coordinate is unexamined input, never an empty passing ref population.
  if ! jq -e -s '
    def nodes: .jobs[] | ., ((.steps // [])[]);
    length == 1 and (.[0] |
      type == "object" and (.jobs | type == "object" and length > 0) and
      all(.jobs[]; type == "object" and
        ((has("steps") | not) or (.steps | type == "array" and all(.[]; type == "object")))) and
      all(nodes | select(has("uses")); .uses | type == "string" and length > 0 and
        (test("\\s") | not) and (contains("\u0000") | not)))
  ' "$scratch" >/dev/null; then
    echo "check-allowed-actions: invalid workflow/ref structure: $file" >&2
    exit 2
  fi
  refs="$(jq -r '.jobs[] | ., ((.steps // [])[]) | select(has("uses")) | .uses' "$scratch")"
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    checked=$((checked + 1))
    if ! covered "$ref"; then
      printf 'GAP  %s: %s (requires an immutable ref and an exact tree-policy match)\n' "$file" "$ref" >&2
      gaps=$((gaps + 1))
    fi
  done <<< "$refs"
done
printf 'checked %s executable uses refs in %s workflow files; %s tree-policy gaps (live policy unverified)\n' \
  "$checked" "${#files[@]}" "$gaps"
[[ "$gaps" -eq 0 ]]
