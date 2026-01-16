#!/bin/bash
# Deployment script - runs on Mac
# Syncs backend to Orange Pi and builds it

set -e

ORANGE_PI_HOST="orangepi@10.0.0.108"
ORANGE_PI_PATH="/opt/appattest-backend"
LOCAL_PATH="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Deploying AppAttest Backend to Orange Pi ==="
echo "Host: $ORANGE_PI_HOST"
echo "Remote path: $ORANGE_PI_PATH"

# Check SSH access
echo "Testing SSH connection..."
if ! ssh -o ConnectTimeout=5 "$ORANGE_PI_HOST" "echo 'SSH connection successful'" 2>/dev/null; then
    echo "ERROR: Cannot connect to Orange Pi. Check SSH access."
    exit 1
fi

# Sync files (exclude build artifacts)
echo "Syncing files..."
rsync -avz --delete \
    --exclude '.build' \
    --exclude '.swiftpm' \
    --exclude '*.xcodeproj' \
    --exclude '*.xcworkspace' \
    --exclude '.git' \
    "$LOCAL_PATH/" "$ORANGE_PI_HOST:$ORANGE_PI_PATH/"

# Build on Orange Pi
echo "Building on Orange Pi..."
ssh "$ORANGE_PI_HOST" "cd $ORANGE_PI_PATH && swift build -c release"

echo "=== Deployment complete ==="
echo "Next steps on Orange Pi:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable appattest-backend"
echo "  sudo systemctl restart appattest-backend"
