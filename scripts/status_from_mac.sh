#!/usr/bin/env bash
# Status check from Mac - three-layer verification
# 
# This script verifies service health from your Mac using three independent layers:
# 1. Process reality (systemd status)
# 2. Binary identity (hash comparison)
# 3. Semantic state (health endpoint)
#
# Usage: ./scripts/status_from_mac.sh [pi-ip]
# Example: ./scripts/status_from_mac.sh 10.0.0.108

set -euo pipefail

PI_IP="${1:-10.0.0.108}"
PI_USER="${PI_USER:-orangepi}"
REPO_PATH="~/Developer/appattest-backend"

echo "=== Layer 1: Process Reality ==="
echo "Question: Is the service alive?"
echo ""
ssh "${PI_USER}@${PI_IP}" "systemctl status appattest-backend --no-pager" 2>&1 | head -15 || {
    echo "⚠️  Could not check systemd status"
}

echo ""
echo "=== Layer 2: Binary Identity ==="
echo "Question: Which exact binary is running?"
echo ""

# Get hash from health endpoint
HEALTH_HASH=$(curl -s "http://${PI_IP}:8080/health" 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('buildSha256', 'unavailable'))" 2>/dev/null || echo "unavailable")

# Get deployed hash from Pi
DEPLOYED_HASH=$(ssh "${PI_USER}@${PI_IP}" "cat ${REPO_PATH}/.deployed_binary_hash 2>/dev/null || echo 'not found'" 2>/dev/null || echo "ssh_failed")

echo "Health endpoint hash: ${HEALTH_HASH}"
echo "Deployed hash:        ${DEPLOYED_HASH}"

if [ "${HEALTH_HASH}" = "${DEPLOYED_HASH}" ] && [ "${HEALTH_HASH}" != "unavailable" ] && [ "${HEALTH_HASH}" != "ssh_failed" ]; then
    echo "✅ Binary identity verified - running the correct binary"
elif [ "${HEALTH_HASH}" = "unavailable" ]; then
    echo "⚠️  Health endpoint unavailable - service may be down"
elif [ "${DEPLOYED_HASH}" = "ssh_failed" ] || [ "${DEPLOYED_HASH}" = "not found" ]; then
    echo "⚠️  Could not read deployed hash from Pi"
else
    echo "❌ Binary identity mismatch - wrong binary may be running"
fi

echo ""
echo "=== Layer 3: Semantic State ==="
echo "Question: Is the service behaving meaningfully?"
echo ""

HEALTH_JSON=$(curl -s "http://${PI_IP}:8080/health" 2>/dev/null || echo '{"status":"unavailable"}')

if command -v jq &> /dev/null; then
    echo "$HEALTH_JSON" | jq '.'
else
    echo "$HEALTH_JSON" | python3 -m json.tool 2>/dev/null || echo "$HEALTH_JSON"
fi

echo ""
echo "=== Interpretation ==="
STATUS=$(echo "$HEALTH_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
UPTIME=$(echo "$HEALTH_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('uptimeSeconds', 0))" 2>/dev/null || echo "0")
KEY_COUNT=$(echo "$HEALTH_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('keyCount', 0))" 2>/dev/null || echo "0")
HASH_COUNT=$(echo "$HEALTH_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('clientDataHashCount', 0))" 2>/dev/null || echo "0")

if [ "$STATUS" = "ok" ]; then
    echo "✅ Service is healthy"
    if (( $(echo "$UPTIME < 60" | bc -l 2>/dev/null || echo "0") )); then
        echo "   ⚠️  Freshly restarted (uptime: ${UPTIME}s)"
    else
        echo "   ✓ Stable (uptime: ${UPTIME}s)"
    fi
    echo "   Keys registered: ${KEY_COUNT}"
    echo "   ClientDataHashes stored: ${HASH_COUNT}"
    if [ "$KEY_COUNT" = "0" ] && [ "$HASH_COUNT" = "0" ]; then
        echo "   ℹ️  No traffic yet (normal for fresh restart)"
    fi
else
    echo "❌ Service status: ${STATUS}"
fi
