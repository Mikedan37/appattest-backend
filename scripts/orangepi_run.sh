#!/bin/bash
# Run script - executes the backend service
# Used by systemd

set -e

cd /home/orangepi/Developer/appattest-backend
BIN_PATH="$(swift build -c release --show-bin-path)/AppAttestBackend"

if [ ! -f "$BIN_PATH" ]; then
    echo "ERROR: Binary not found at $BIN_PATH"
    echo "Run: cd /home/orangepi/Developer/appattest-backend && swift build -c release"
    exit 1
fi

exec "$BIN_PATH"
