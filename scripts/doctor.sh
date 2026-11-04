#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
# Local availability probes; no repair or telemetry requested.
# Disable implicit rustup installs on rustup >= 1.28.1. Older/external shims
# may have their own side effects; these probes are not a process sandbox.
set -u
failed=0
for tool in cargo rustc git just; do
    if command -v "$tool" >/dev/null 2>&1 && RUSTUP_AUTO_INSTALL=0 "$tool" --version >/dev/null 2>&1; then
        printf '[OK] %s responds to --version\n' "$tool"
    else
        printf '[FAIL] %s missing or unable to run\n' "$tool" >&2
        failed=1
    fi
done
printf '%s\n' 'Availability only: use cargo build --locked --release to check compiler and dependency compatibility.'
exit "$failed"
