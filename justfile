# SPDX-License-Identifier: PMPL-1.0-or-later
# panic-attack justfile

# Default recipe: build and test
default: build test

# Build release binary
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run only the readiness tests (machine-verifiable CRG grades)
readiness:
    @echo "Running Component Readiness Grade verification..."
    cargo test --test readiness -- --nocapture 2>&1 | tee /tmp/panic-attack-readiness.log
    @echo ""
    @echo "Results saved to /tmp/panic-attack-readiness.log"
    @echo "Grade D tests = component runs without crashing"
    @echo "Grade C tests = component produces correct output"
    @echo "Grade B tests = edge cases and multi-input support"

# Run readiness tests and summarise pass/fail per grade
readiness-summary:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Component Readiness Grade Verification ==="
    echo ""
    output=$(cargo test --test readiness 2>&1)
    d_pass=$(echo "$output" | grep -c "readiness_d.*ok" || true)
    d_fail=$(echo "$output" | grep -c "readiness_d.*FAILED" || true)
    c_pass=$(echo "$output" | grep -c "readiness_c.*ok" || true)
    c_fail=$(echo "$output" | grep -c "readiness_c.*FAILED" || true)
    b_pass=$(echo "$output" | grep -c "readiness_b.*ok" || true)
    b_fail=$(echo "$output" | grep -c "readiness_b.*FAILED" || true)
    total_pass=$((d_pass + c_pass + b_pass))
    total_fail=$((d_fail + c_fail + b_fail))
    echo "Grade D (Alpha):  $d_pass passed, $d_fail failed"
    echo "Grade C (Beta):   $c_pass passed, $c_fail failed"
    echo "Grade B (RC):     $b_pass passed, $b_fail failed"
    echo "---"
    echo "Total: $total_pass passed, $total_fail failed"
    if [ "$total_fail" -eq 0 ]; then
        echo ""
        echo "All readiness tests pass."
    else
        echo ""
        echo "Some readiness tests failed. Review output above."
        exit 1
    fi

# Clean build artifacts
clean:
    cargo clean

# Install to system
install: build
    cp target/release/panic-attack ~/.local/bin/

# Scan self (dogfood)
dogfood:
    cargo run --release -- assail .

# Run assemblyline on all repos
assemblyline:
    cargo run --release -- assemblyline ~/Documents/hyperpolymath-repos/

# Lint (check warnings)
lint:
    cargo build --release 2>&1 | grep -c "warning" || echo "0 warnings"
