#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec cargo run --quiet --locked --manifest-path "$root/tools/ci/Cargo.toml" --bin recon-compare -- "$@"
