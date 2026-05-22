#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if command -v podman >/dev/null 2>&1; then
  OCI_ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
  OCI_ENGINE="docker"
else
  echo "ERROR: neither podman nor docker is available."
  exit 1
fi

if ! command -v ct >/dev/null 2>&1; then
  echo "ERROR: ct (Cerro Torre) is required but was not found in PATH."
  exit 1
fi

IMAGE_REF="${PANIC_ATTACK_IMAGE_REF:-localhost/panic-attack:dev}"
BUNDLE_OUT="${PANIC_ATTACK_BUNDLE_OUT:-runtime/out/panic-attack.ctp}"
POLICY="${PANIC_ATTACK_CT_POLICY:-strict}"
POLICY_FILE="${PANIC_ATTACK_CT_POLICY_FILE:-}"

mkdir -p "$(dirname "$BUNDLE_OUT")"

printf "==> Building Chainguard-backed panic-attack runtime: %s\n" "$IMAGE_REF"
"$OCI_ENGINE" build -f runtime/Containerfile -t "$IMAGE_REF" .

printf "==> Packing with Cerro Torre: %s\n" "$BUNDLE_OUT"
ct pack "$IMAGE_REF" -o "$BUNDLE_OUT"

printf "==> Verifying bundle"
if [[ -n "$POLICY_FILE" ]]; then
  ct verify "$BUNDLE_OUT" --policy "$POLICY_FILE"
else
  ct verify "$BUNDLE_OUT" --policy "$POLICY"
fi

echo "OK: panic-attack bundle built and verified -> $BUNDLE_OUT"
