#!/usr/bin/env bash
# Run script - executes the backend service
# Used by systemd
# 
# CRITICAL: This script does NOT build. Build manually with:
#   cd /home/orangepi/Developer/appattest-backend && swift build -c release

set -e

BIN="/home/orangepi/Developer/appattest-backend/.build/aarch64-unknown-linux-gnu/release/AppAttestBackend"

if [ ! -x "$BIN" ]; then
    echo "FATAL: Binary missing or not executable: $BIN"
    echo "Build it first: cd /home/orangepi/Developer/appattest-backend && swift build -c release"
    exit 1
fi

# CRITICAL: Bundle ID must exactly match iOS app bundle identifier
export APP_BUNDLE_ID="${APP_BUNDLE_ID:-DanylchukStudios.AppAttestDecoderTestApp}"

# CRITICAL: Team ID is required for rpIdHash validation
# appID = "<TEAM_ID>.<BUNDLE_ID>"
# rpIdHash = SHA256(appID UTF-8)
# If not set, verification will fail with "APP_TEAM_ID not set"
export APP_TEAM_ID="${APP_TEAM_ID:-}"

exec "$BIN"
