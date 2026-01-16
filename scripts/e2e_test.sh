#!/bin/bash
# End-to-End Verification Test Script
# Tests the complete App Attest verification pipeline

set -e

BASE_URL="${1:-http://127.0.0.1:8080}"
TEST_RESULTS="/tmp/appattest_e2e_results.txt"

echo "=== App Attest Backend E2E Verification ===" > "$TEST_RESULTS"
echo "Base URL: $BASE_URL" >> "$TEST_RESULTS"
echo "Started: $(date)" >> "$TEST_RESULTS"
echo "" >> "$TEST_RESULTS"

PASSED=0
FAILED=0

# Helper function to run test
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected="$3"
    
    echo ""
    echo "Test: $test_name"
    echo "Command: $test_cmd"
    
    local response
    response=$(eval "$test_cmd" 2>&1)
    local exit_code=$?
    
    echo "Response: $response"
    echo "Exit code: $exit_code"
    
    if echo "$response" | grep -q "$expected"; then
        echo "✅ PASSED"
        echo "[PASS] $test_name" >> "$TEST_RESULTS"
        ((PASSED++))
        return 0
    else
        echo "❌ FAILED"
        echo "Expected: $expected"
        echo "[FAIL] $test_name" >> "$TEST_RESULTS"
        echo "  Response: $response" >> "$TEST_RESULTS"
        ((FAILED++))
        return 1
    fi
}

# Test 1: Health Check
echo "=== Test 1: Health Check ===" | tee -a "$TEST_RESULTS"
run_test "Health Check" \
    "curl -s $BASE_URL/health" \
    '"status":"ok"'

# Test 2: Real Assertion Test
echo "" | tee -a "$TEST_RESULTS"
echo "=== Test 2: Real Assertion Verification ===" | tee -a "$TEST_RESULTS"
echo "NOTE: This test requires a real iOS-generated assertion." | tee -a "$TEST_RESULTS"
echo "To run this test:" | tee -a "$TEST_RESULTS"
echo "  1. Generate assertion from iOS app" | tee -a "$TEST_RESULTS"
echo "  2. Save to file: /tmp/real_assertion.json" | tee -a "$TEST_RESULTS"
echo "  3. Ensure public key exists: /opt/appattest/keys/<keyID>.pub" | tee -a "$TEST_RESULTS"
echo "" | tee -a "$TEST_RESULTS"

if [ -f "/tmp/real_assertion.json" ]; then
    echo "Found real assertion file, running test..."
    REAL_ASSERTION=$(cat /tmp/real_assertion.json)
    run_test "Real Assertion Verification" \
        "curl -s -X POST $BASE_URL/app-attest/verify -H 'Content-Type: application/json' -d '$REAL_ASSERTION'" \
        '"status":"verified"'
else
    echo "⚠️  SKIPPED: No real assertion file found at /tmp/real_assertion.json" | tee -a "$TEST_RESULTS"
    echo "  To create test file, use format:" | tee -a "$TEST_RESULTS"
    echo '  {"keyID":"your-key-id","assertionObject":"base64...","clientDataHash":"base64..."}' | tee -a "$TEST_RESULTS"
    echo "[SKIP] Real Assertion Verification (no test data)" >> "$TEST_RESULTS"
fi

# Test 3: Tamper Test
echo "" | tee -a "$TEST_RESULTS"
echo "=== Test 3: Tamper Detection ===" | tee -a "$TEST_RESULTS"

if [ -f "/tmp/real_assertion.json" ]; then
    # Load real assertion
    REAL_ASSERTION=$(cat /tmp/real_assertion.json)
    
    # Extract assertionObject and flip one byte
    ASSERTION_OBJ=$(echo "$REAL_ASSERTION" | jq -r '.assertionObject')
    KEY_ID=$(echo "$REAL_ASSERTION" | jq -r '.keyID')
    CLIENT_HASH=$(echo "$REAL_ASSERTION" | jq -r '.clientDataHash')
    
    # Decode base64, flip first byte, re-encode
    # Use Python for reliable byte manipulation
    TAMPERED_OBJ=$(python3 << EOF
import base64
import sys

original = "$ASSERTION_OBJ"
decoded = base64.b64decode(original)
if len(decoded) > 0:
    # Flip first byte
    tampered = bytearray(decoded)
    tampered[0] = (tampered[0] + 1) % 256
    tampered_bytes = bytes(tampered)
    print(base64.b64encode(tampered_bytes).decode('utf-8'))
else:
    # Fallback: flip last char of base64 string
    print(original[:-1] + 'X')
EOF
)
    
    # Fallback if Python fails
    if [ -z "$TAMPERED_OBJ" ] || [ "$TAMPERED_OBJ" == "$ASSERTION_OBJ" ]; then
        # Simple approach: flip last character of base64
        TAMPERED_OBJ="${ASSERTION_OBJ%?}X"
    fi
    
    TAMPERED_JSON=$(jq -n \
        --arg keyID "$KEY_ID" \
        --arg assertionObject "$TAMPERED_OBJ" \
        --arg clientDataHash "$CLIENT_HASH" \
        '{keyID: $keyID, assertionObject: $assertionObject, clientDataHash: $clientDataHash}')
    
    echo "Original assertionObject (last 20 chars): ${ASSERTION_OBJ: -20}"
    echo "Tampered assertionObject (last 20 chars): ${TAMPERED_OBJ: -20}"
    
    run_test "Tamper Detection" \
        "curl -s -X POST $BASE_URL/app-attest/verify -H 'Content-Type: application/json' -d '$TAMPERED_JSON'" \
        '"status":"rejected"'
else
    # Create a synthetic tamper test with obviously wrong data
    echo "⚠️  Using synthetic tamper test (no real assertion available)" | tee -a "$TEST_RESULTS"
    
    # Create obviously invalid assertion
    TAMPERED_JSON='{"keyID":"test-key","assertionObject":"dGVzdFRBTVBFUkVE","clientDataHash":"dGVzdA=="}'
    
    run_test "Tamper Detection (synthetic)" \
        "curl -s -X POST $BASE_URL/app-attest/verify -H 'Content-Type: application/json' -d '$TAMPERED_JSON'" \
        '"status":"rejected"'
fi

# Summary
echo "" | tee -a "$TEST_RESULTS"
echo "=== Test Summary ===" | tee -a "$TEST_RESULTS"
echo "Passed: $PASSED" | tee -a "$TEST_RESULTS"
echo "Failed: $FAILED" | tee -a "$TEST_RESULTS"
echo "Completed: $(date)" | tee -a "$TEST_RESULTS"

if [ $FAILED -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
    exit 0
else
    echo ""
    echo "❌ Some tests failed. See $TEST_RESULTS for details."
    exit 1
fi
