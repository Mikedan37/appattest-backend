#!/bin/bash
# Bootstrap script for Orange Pi
# Installs Swift and required dependencies

set -e

echo "=== AppAttest Backend Bootstrap ==="

# Check if Swift is installed
if ! command -v swift &> /dev/null; then
    echo "ERROR: Swift is not installed. Please install Swift first."
    echo "Visit: https://www.swift.org/download/"
    exit 1
fi

SWIFT_VERSION=$(swift --version | head -n1)
echo "Found: $SWIFT_VERSION"

# Check for required system libraries
echo "Checking system dependencies..."
REQUIRED_PKGS=("libssl-dev" "libz-dev" "libsqlite3-dev")
MISSING_PKGS=()

for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -ne 0 ]; then
    echo "Installing missing packages: ${MISSING_PKGS[*]}"
    sudo apt-get update
    sudo apt-get install -y "${MISSING_PKGS[@]}"
fi

# Create directories
echo "Creating directories..."
sudo mkdir -p /opt/appattest/keys
sudo mkdir -p /opt/appattest-backend
sudo chown -R $USER:$USER /opt/appattest

# Set permissions
chmod 700 /opt/appattest/keys

echo "=== Bootstrap complete ==="
