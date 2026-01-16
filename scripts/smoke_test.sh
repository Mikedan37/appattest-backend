#!/bin/bash
# Smoke test script
# Tests health and verify-assertion endpoints

set -e

BASE_URL="${1:-http://127.0.0.1:8080}"

echo "=== AppAttest Backend Smoke Test ==="
echo "Testing: $BASE_URL"

# Test health endpoint
echo ""
echo "1. Testing /health..."
HEALTH_RESPONSE=$(curl -s "$BASE_URL/health")
if echo "$HEALTH_RESPONSE" | grep -q '"status":"ok"'; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    echo "Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test verify-assertion with missing fields
echo ""
echo "2. Testing /app-attest/verify-assertion with missing fields..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/app-attest/verify-assertion" \
    -H "Content-Type: application/json" \
    -d '{}')

if echo "$VERIFY_RESPONSE" | grep -q '"status":"cannotValidate"'; then
    echo "✅ Missing fields correctly rejected"
else
    echo "❌ Missing fields test failed"
    echo "Response: $VERIFY_RESPONSE"
    exit 1
fi

# Test verify-assertion with invalid base64
echo ""
echo "3. Testing /app-attest/verify-assertion with invalid base64..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/app-attest/verify-assertion" \
    -H "Content-Type: application/json" \
    -d '{
        "keyID": "test-key",
        "assertionObjectBase64": "invalid-base64!!!",
        "clientDataHashBase64": "dGVzdA=="
    }')

if echo "$VERIFY_RESPONSE" | grep -q '"status":"cannotValidate"'; then
    echo "✅ Invalid base64 correctly rejected"
else
    echo "❌ Invalid base64 test failed"
    echo "Response: $VERIFY_RESPONSE"
    exit 1
fi

# Test verify-assertion with missing key
echo ""
echo "4. Testing /app-attest/verify-assertion with missing public key..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/app-attest/verify-assertion" \
    -H "Content-Type: application/json" \
    -d '{
        "keyID": "nonexistent-key",
        "assertionObjectBase64": "dGVzdA==",
        "clientDataHashBase64": "dGVzdA=="
    }')

if echo "$VERIFY_RESPONSE" | grep -q '"status":"cannotValidate"'; then
    echo "✅ Missing key correctly rejected"
    if echo "$VERIFY_RESPONSE" | grep -q "Public key not found"; then
        echo "✅ Reason message is clear"
    fi
else
    echo "❌ Missing key test failed"
    echo "Response: $VERIFY_RESPONSE"
    exit 1
fi

echo ""
echo "=== All smoke tests passed ==="
