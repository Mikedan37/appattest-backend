#!/usr/bin/env bash
# Fast build for testing: incremental, debug, no clean, no deploy.
# Use when you only need "does it compile" or to run the binary by hand.
#
# Usage: ./scripts/build-fast.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# SwiftPM uses <arch>-unknown-linux-gnu (aarch64 on Pi, x86_64 on Intel)
BUILD_SUBDIR="$(uname -m)-unknown-linux-gnu"
BIN_PATH="$REPO_ROOT/.build/$BUILD_SUBDIR/debug/AppAttestBackend"

cd "$REPO_ROOT"

echo "=== FAST BUILD (debug, incremental) ==="
swift build -c debug --product AppAttestBackend

if [[ -f "$BIN_PATH" ]]; then
    echo "  -> $BIN_PATH"
    echo "  Run: $BIN_PATH  (or use for tests; service uses release binary)"
else
    echo "  Binary not at $BIN_PATH (arch may differ); find with: find .build -name AppAttestBackend -type f"
fi
