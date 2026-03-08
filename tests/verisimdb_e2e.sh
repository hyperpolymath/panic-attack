#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# End-to-end integration test: panic-attack hexad storage via the VeriSimDB
# V-lang REST gateway.
#
# Prerequisites:
#   - VeriSimDB REST gateway running on localhost:9090
#     (cd developer-ecosystem/v-ecosystem/v-api-interfaces/verisimdb-rest
#      && v run src/rest.v)
#   - curl available on PATH
#
# The test is self-contained: it creates sample hexads, POSTs them, queries
# them back, and verifies the responses.  If the gateway is not running the
# test exits 0 (skip) so CI pipelines are not blocked.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY="${VERISIM_API_URL:-http://localhost:9090}"
PASS=0
FAIL=0
SKIP=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

pass() { PASS=$((PASS + 1)); green "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); red   "  FAIL: $1 — $2"; }
skip() { SKIP=$((SKIP + 1)); yellow "  SKIP: $1"; }

# Assert that a string ($2) contains a substring ($3).
# $1 = test label
assert_contains() {
    local label="$1" body="$2" needle="$3"
    if echo "$body" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label" "expected body to contain '$needle'"
        echo "    body was: ${body:0:200}"
    fi
}

# Assert HTTP status code.  $1 = label, $2 = expected status, $3 = actual.
assert_status() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label" "expected HTTP $expected, got HTTP $actual"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight: check gateway availability
# ---------------------------------------------------------------------------

echo "========================================"
echo " VeriSimDB E2E Integration Test"
echo " Gateway: ${GATEWAY}"
echo "========================================"
echo ""

echo "[1/6] Checking gateway availability..."
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${GATEWAY}/api/v1/health" 2>/dev/null || true)

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
    yellow "Gateway not reachable at ${GATEWAY} — skipping all tests."
    yellow "Start the gateway with:"
    yellow "  cd developer-ecosystem/v-ecosystem/v-api-interfaces/verisimdb-rest"
    yellow "  v run src/rest.v"
    exit 0
fi

assert_status "Health endpoint reachable" "200" "$HTTP_CODE"

# Verify health response body
HEALTH_BODY=$(curl -s --max-time 5 "${GATEWAY}/api/v1/health")
assert_contains "Health body has 'healthy'" "$HEALTH_BODY" '"healthy":true'
assert_contains "Health body identifies service" "$HEALTH_BODY" '"service":"verisimdb-rest"'

echo ""

# ---------------------------------------------------------------------------
# Test 2: POST a single hexad
# ---------------------------------------------------------------------------

echo "[2/6] POST single hexad..."

HEXAD_ID="pa-e2e-$(date +%Y%m%d%H%M%S)-$(printf '%04x' $$)"

HEXAD_JSON=$(cat <<ENDJSON
{
    "schema": "verisimdb.hexad.v1",
    "id": "${HEXAD_ID}",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "provenance": {
        "tool": "panic-attack",
        "version": "2.1.0",
        "program_path": "/tmp/e2e-test-target",
        "language": "Rust"
    },
    "semantic": {
        "total_weak_points": 7,
        "critical_count": 1,
        "high_count": 2,
        "total_crashes": 0,
        "robustness_score": 0.78,
        "categories": ["UnsafeCode", "PanicPath", "UnsafeFFI"]
    },
    "document": {
        "program_path": "/tmp/e2e-test-target",
        "total_files_scanned": 42,
        "total_weak_points": 7,
        "summary": "E2E integration test hexad"
    }
}
ENDJSON
)

RESPONSE=$(curl -s -w '\n%{http_code}' --max-time 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$HEXAD_JSON" \
    "${GATEWAY}/api/v1/hexads")

POST_BODY=$(echo "$RESPONSE" | head -n -1)
POST_STATUS=$(echo "$RESPONSE" | tail -n 1)

assert_status "POST /api/v1/hexads returns 201" "201" "$POST_STATUS"
assert_contains "POST response confirms stored" "$POST_BODY" '"stored":true'
assert_contains "POST response contains hexad ID" "$POST_BODY" "\"id\":\"${HEXAD_ID}\""

echo ""

# ---------------------------------------------------------------------------
# Test 3: GET hexad by ID
# ---------------------------------------------------------------------------

echo "[3/6] GET hexad by ID..."

RESPONSE=$(curl -s -w '\n%{http_code}' --max-time 5 \
    "${GATEWAY}/api/v1/hexads/${HEXAD_ID}")

GET_BODY=$(echo "$RESPONSE" | head -n -1)
GET_STATUS=$(echo "$RESPONSE" | tail -n 1)

assert_status "GET /api/v1/hexads/:id returns 200" "200" "$GET_STATUS"
assert_contains "GET body contains hexad ID" "$GET_BODY" "\"id\":\"${HEXAD_ID}\""
assert_contains "GET body contains schema" "$GET_BODY" '"schema":"verisimdb.hexad.v1"'
assert_contains "GET body contains tool" "$GET_BODY" '"tool":"panic-attack"'

echo ""

# ---------------------------------------------------------------------------
# Test 4: Query hexads by tool
# ---------------------------------------------------------------------------

echo "[4/6] GET hexads?tool=panic-attack..."

RESPONSE=$(curl -s -w '\n%{http_code}' --max-time 5 \
    "${GATEWAY}/api/v1/hexads?tool=panic-attack&limit=10")

QUERY_BODY=$(echo "$RESPONSE" | head -n -1)
QUERY_STATUS=$(echo "$RESPONSE" | tail -n 1)

assert_status "GET /api/v1/hexads?tool=... returns 200" "200" "$QUERY_STATUS"
assert_contains "Query response has hexads array" "$QUERY_BODY" '"hexads":['
assert_contains "Query response contains our hexad" "$QUERY_BODY" "$HEXAD_ID"

echo ""

# ---------------------------------------------------------------------------
# Test 5: Batch upload
# ---------------------------------------------------------------------------

echo "[5/6] POST batch of hexads..."

BATCH_ID_1="pa-e2e-batch1-$(date +%Y%m%d%H%M%S)-$(printf '%04x' $$)"
BATCH_ID_2="pa-e2e-batch2-$(date +%Y%m%d%H%M%S)-$(printf '%04x' $$)"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

BATCH_JSON=$(cat <<ENDJSON
[
    {
        "schema": "verisimdb.hexad.v1",
        "id": "${BATCH_ID_1}",
        "created_at": "${NOW_ISO}",
        "provenance": {
            "tool": "panic-attack",
            "version": "2.1.0",
            "program_path": "/tmp/e2e-batch-target-1",
            "language": "Elixir"
        },
        "semantic": {
            "total_weak_points": 3,
            "critical_count": 0,
            "high_count": 1,
            "total_crashes": 0,
            "robustness_score": 0.92,
            "categories": ["AtomExhaustion", "PanicPath"]
        },
        "document": {"summary": "Batch test hexad 1"}
    },
    {
        "schema": "verisimdb.hexad.v1",
        "id": "${BATCH_ID_2}",
        "created_at": "${NOW_ISO}",
        "provenance": {
            "tool": "panic-attack",
            "version": "2.1.0",
            "program_path": "/tmp/e2e-batch-target-2",
            "language": "Gleam"
        },
        "semantic": {
            "total_weak_points": 1,
            "critical_count": 0,
            "high_count": 0,
            "total_crashes": 0,
            "robustness_score": 0.98,
            "categories": ["PanicPath"]
        },
        "document": {"summary": "Batch test hexad 2"}
    }
]
ENDJSON
)

RESPONSE=$(curl -s -w '\n%{http_code}' --max-time 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$BATCH_JSON" \
    "${GATEWAY}/api/v1/hexads/batch")

BATCH_BODY=$(echo "$RESPONSE" | head -n -1)
BATCH_STATUS=$(echo "$RESPONSE" | tail -n 1)

assert_status "POST /api/v1/hexads/batch returns 201" "201" "$BATCH_STATUS"
assert_contains "Batch response stored count" "$BATCH_BODY" '"stored":2'
assert_contains "Batch response contains first ID" "$BATCH_BODY" "$BATCH_ID_1"
assert_contains "Batch response contains second ID" "$BATCH_BODY" "$BATCH_ID_2"

echo ""

# ---------------------------------------------------------------------------
# Test 6: API discovery endpoint
# ---------------------------------------------------------------------------

echo "[6/6] GET / (API discovery)..."

RESPONSE=$(curl -s -w '\n%{http_code}' --max-time 5 "${GATEWAY}/")

DISC_BODY=$(echo "$RESPONSE" | head -n -1)
DISC_STATUS=$(echo "$RESPONSE" | tail -n 1)

assert_status "GET / returns 200" "200" "$DISC_STATUS"
assert_contains "Discovery lists service name" "$DISC_BODY" '"service":"verisimdb-rest"'
assert_contains "Discovery lists hexads endpoint" "$DISC_BODY" '"/api/v1/hexads"'

echo ""

# ---------------------------------------------------------------------------
# Cleanup: remove the test hexads we created
# ---------------------------------------------------------------------------

# No DELETE endpoint exists yet, so we leave them.  The gateway stores
# hexads as files under VERISIMDB_DATA_DIR; they can be removed manually.

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "========================================"
echo " Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    red "Some tests failed."
    exit 1
else
    green "All tests passed."
    exit 0
fi
