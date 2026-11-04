#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Local, read-only availability probes. No network, repair, or telemetry.
set -u
failed=0
for tool in cargo rustc git just; do
    if command -v "$tool" >/dev/null 2>&1 && "$tool" --version >/dev/null 2>&1; then
        printf '[OK] %s responds to --version\n' "$tool"
    else
        printf '[FAIL] %s missing or unable to run\n' "$tool" >&2
        failed=1
    fi
done
printf '%s\n' 'Availability only: use cargo build --locked --release to check compiler and dependency compatibility.'
exit "$failed"
