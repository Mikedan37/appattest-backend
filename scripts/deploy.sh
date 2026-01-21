#!/usr/bin/env bash
# Deploy script - Build and deploy with invariant checking
# 
# HARD RULES:
# 1. Service only restarts if build succeeds
# 2. Binary hash must change for restart
# 3. Fail loudly if invariants violated
#
# Usage: ./scripts/deploy.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_PATH="$REPO_ROOT/.build/aarch64-unknown-linux-gnu/release/AppAttestBackend"
HASH_FILE="$REPO_ROOT/.deployed_binary_hash"
SERVICE_NAME="appattest-backend"

cd "$REPO_ROOT"

echo "=== DEPLOY: Starting deployment with invariant checks ==="

# Step 1: Build (clean unless SKIP_CLEAN=1 for faster incremental)
if [[ -n "${SKIP_CLEAN:-}" ]]; then
    echo "[1/5] Running incremental release build (SKIP_CLEAN=1)..."
else
    echo "[1/5] Running clean release build..."
    rm -rf .build
fi
echo "  (Linking on ARM can take 5–15 min. Run ./scripts/link-heartbeat.sh in another terminal to confirm it's alive. See docs/BUILD_LINK_PHASE.md)"
if ! swift build -c release --product AppAttestBackend ${LINKER_EXTRA_FLAGS:-}; then
    echo "FATAL: Build failed. Service will NOT restart."
    exit 1
fi

# Step 2: Verify binary exists and strip
echo "[2/5] Verifying binary and stripping..."
if [ ! -f "$BIN_PATH" ]; then
    echo "FATAL: Binary not found at $BIN_PATH"
    echo "Build claimed success but no binary produced. This is a SwiftPM bug."
    exit 1
fi

if [ ! -x "$BIN_PATH" ]; then
    echo "FATAL: Binary exists but is not executable: $BIN_PATH"
    exit 1
fi

strip "$BIN_PATH"
echo "  Stripped."

# Step 3: Compute binary hash
echo "[3/5] Computing binary SHA256..."
NEW_HASH=$(sha256sum "$BIN_PATH" | cut -d' ' -f1)
BIN_TIMESTAMP=$(stat -c "%y" "$BIN_PATH")
BIN_SIZE=$(stat -c "%s" "$BIN_PATH")

echo "  Binary: $BIN_PATH"
echo "  Size: $BIN_SIZE bytes"
echo "  Timestamp: $BIN_TIMESTAMP"
echo "  SHA256: $NEW_HASH"

# Step 4: Compare to last deployed hash
echo "[4/5] Checking if binary changed..."
if [ -f "$HASH_FILE" ]; then
    OLD_HASH=$(cat "$HASH_FILE")
    if [ "$NEW_HASH" = "$OLD_HASH" ]; then
        echo "WARNING: Binary hash unchanged ($NEW_HASH)"
        echo "  Service will NOT restart (no changes detected)"
        echo "  To force restart, delete $HASH_FILE and run again"
        exit 0
    else
        echo "  Hash changed: $OLD_HASH -> $NEW_HASH"
    fi
else
    echo "  No previous hash found (first deployment)"
fi

# Step 5: Restart service
echo "[5/5] Restarting service..."
sudo systemctl daemon-reload
if ! sudo systemctl restart "$SERVICE_NAME"; then
    echo "FATAL: Service restart failed. Previous version may still be running."
    exit 1
fi

# Step 6: Persist hash
echo "$NEW_HASH" > "$HASH_FILE"
echo "  Deployed hash saved to $HASH_FILE"

# Step 7: Verify service is running
sleep 2
if ! sudo systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "FATAL: Service is not running after restart"
    sudo systemctl status "$SERVICE_NAME" --no-pager -l || true
    exit 1
fi

echo "=== DEPLOY: Success ==="
echo "  Service: $SERVICE_NAME"
echo "  Binary: $BIN_PATH"
echo "  Hash: $NEW_HASH"
echo ""
echo "Verify logs with: sudo journalctl -u $SERVICE_NAME -n 20"
