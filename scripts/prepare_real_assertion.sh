#!/bin/bash
# Helper script to prepare real assertion test data
# Run this after generating an assertion from your iOS app

set -e

echo "=== Prepare Real Assertion Test Data ==="
echo ""
echo "This script helps you prepare a real iOS assertion for testing."
echo ""

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "ERROR: jq is required. Install with: sudo apt-get install jq"
    exit 1
fi

OUTPUT_FILE="/tmp/real_assertion.json"

echo "Enter assertion data from your iOS app:"
echo ""

read -p "KeyID: " KEY_ID
read -p "Assertion Object (base64): " ASSERTION_OBJ
read -p "Client Data Hash (base64): " CLIENT_HASH

# Validate inputs
if [ -z "$KEY_ID" ] || [ -z "$ASSERTION_OBJ" ] || [ -z "$CLIENT_HASH" ]; then
    echo "ERROR: All fields are required"
    exit 1
fi

# Create JSON
jq -n \
    --arg keyID "$KEY_ID" \
    --arg assertionObject "$ASSERTION_OBJ" \
    --arg clientDataHash "$CLIENT_HASH" \
    '{keyID: $keyID, assertionObject: $assertionObject, clientDataHash: $clientDataHash}' \
    > "$OUTPUT_FILE"

echo ""
echo "✅ Test data saved to: $OUTPUT_FILE"
echo ""
echo "Verify the public key exists:"
echo "  ls -lh /opt/appattest/keys/${KEY_ID}.pub"
echo ""
echo "Then run:"
echo "  ./scripts/e2e_test.sh"
