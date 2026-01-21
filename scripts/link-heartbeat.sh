#!/usr/bin/env bash
# Link-phase heartbeat: run in another terminal while `swift build -c release` runs.
# Shows that the build is alive during the long, opaque linking step on ARM.
#
# During linking, `ps | grep swiftc` often shows nothing. This script checks:
#   - binary/artifact timestamps (linker is still writing)
#   - RAM and swap
#   - ld / swift / cc1 processes
#
# Usage: ./scripts/link-heartbeat.sh [BINARY_PATH]
#   BINARY_PATH defaults to .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
#
# Run in a second terminal: while the build runs, this prints every 30s.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_BIN="$REPO_ROOT/.build/aarch64-unknown-linux-gnu/release/AppAttestBackend"
BIN="${1:-$DEFAULT_BIN}"
INTERVAL="${LINK_HEARTBEAT_INTERVAL:-30}"

cd "$REPO_ROOT"

echo "=== Link heartbeat (every ${INTERVAL}s) — binary: $BIN ==="
echo ""

while true; do
  TS=$(date '+%H:%M:%S')
  echo "--- $TS ---"

  # 1. Binary or artifact timestamps
  if [[ -f "$BIN" ]]; then
    stat -c "  binary: %s bytes, mtime %y" "$BIN" 2>/dev/null || ls -l "$BIN"
  else
    echo "  binary: not yet (link still in progress or build not started)"
    # Show recently touched files in .build (linker/ar activity)
    RECENT=$(find "$REPO_ROOT/.build" -type f -mmin -2 2>/dev/null | head -3)
    if [[ -n "$RECENT" ]]; then
      echo "  .build recent (last 2 min):"
      echo "$RECENT" | sed 's/^/    /'
    fi
  fi

  # 2. Memory
  echo "  $(free -h | awk '/^Mem:/{printf "RAM: %s / %s", $3, $2}')  $(free -h | awk '/^Swap:/{printf "Swap: %s / %s", $3, $2}')"

  # 3. Linker / Swift / compiler processes (often empty during link — that's normal)
  PROCS=$(ps -eo pid,pcpu,pmem,comm 2>/dev/null | grep -E 'ld|swift|swiftc|cc1' | grep -v grep || true)
  if [[ -n "$PROCS" ]]; then
    echo "  procs:"
    echo "$PROCS" | sed 's/^/    /'
  else
    echo "  procs: (none visible — normal during link; SwiftPM holds the process)"
  fi

  echo ""
  sleep "$INTERVAL"
done
