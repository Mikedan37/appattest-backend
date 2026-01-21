# How This Prevents "Wrong Binary Running" Bugs

## The Problem You Just Solved

You were debugging code that didn't match the running binary. This happens when:

1. **Source code** - You edit `main.swift`, add logging, fix error handling
2. **Build system** - SwiftPM builds tests, fails silently, or produces partial artifacts
3. **Service** - systemd restarts using a stale binary from yesterday
4. **Debugging** - You read logs from a binary that doesn't match your source code

**Result:** Hours wasted debugging the wrong thing.

## The Solution: Deployment Invariants

### Invariant 1: Build Must Succeed

**Before:** `swift build` could fail, but you'd still restart the service.

**After:** Deploy script checks exit code. If build fails, script aborts and service doesn't restart.

```bash
if ! swift build -c release --product AppAttestBackend; then
    echo "FATAL: Build failed. Service will NOT restart."
    exit 1
fi
```

### Invariant 2: Binary Must Exist

**Before:** SwiftPM could claim "success" but not produce a binary (common with test failures).

**After:** Deploy script verifies binary exists and is executable.

```bash
if [ ! -f "$BIN_PATH" ]; then
    echo "FATAL: Binary not found at $BIN_PATH"
    exit 1
fi
```

### Invariant 3: Binary Hash Must Change

**Before:** You'd restart the service even if nothing changed, wasting time.

**After:** Deploy script compares SHA256 to last deployed hash. If unchanged, service doesn't restart.

```bash
if [ "$NEW_HASH" = "$OLD_HASH" ]; then
    echo "WARNING: Binary hash unchanged. Service will NOT restart."
    exit 0
fi
```

### Invariant 4: Service Logs Binary Identity

**Before:** You had no way to verify which binary was running.

**After:** Every startup logs:
- `exe_path` - Full path to binary
- `binary_sha256` - SHA256 hash of the binary
- `binary_timestamp` - File modification time
- `binary_size_bytes` - File size

**You can now grep logs to verify the running binary matches your source.**

### Invariant 5: No Silent Failures

**Before:** Build could fail silently, service could restart with wrong binary, no one would know.

**After:** Every step fails loudly. If anything goes wrong, you know immediately.

## The Deploy Script Flow

```
1. Clean build directory
   ↓
2. Run swift build -c release --product AppAttestBackend
   ↓ (if fails → abort, service untouched)
3. Verify binary exists and is executable
   ↓ (if missing → abort, service untouched)
4. Compute binary SHA256
   ↓
5. Compare to last deployed hash
   ↓ (if unchanged → exit, service untouched)
6. Restart systemd service
   ↓ (if fails → abort, show status)
7. Save new hash to .deployed_binary_hash
   ↓
8. Verify service is running
   ↓
SUCCESS
```

**At every step, if something fails, the script aborts and the service remains untouched.**

## How to Use

### Normal Deployment

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/deploy.sh
```

**This is the ONLY way you should deploy.** It enforces all invariants.

### Verify Running Binary

After deployment, verify the binary matches:

```bash
# Check logs
sudo journalctl -u appattest-backend -n 20 | grep "CANARY"

# Check health endpoint
curl http://localhost:8080/health

# Compare hashes
cat .deployed_binary_hash
sha256sum .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

**If hashes match, you're running the binary you think you are.**

## Why This Works

### Before (Broken)

```
You: Edit code
You: swift build
SwiftPM: (builds tests, fails, but you don't notice)
You: sudo systemctl restart
Systemd: (restarts old binary from yesterday)
You: Check logs
Logs: (from old binary, doesn't match your code)
You: "Why isn't my fix working?"
```

### After (Fixed)

```
You: Edit code
You: ./scripts/deploy.sh
Script: swift build -c release --product AppAttestBackend
Script: (build succeeds, binary exists)
Script: (hash changed, restarting service)
Service: (starts, logs binary_sha256)
You: Check logs
Logs: (binary_sha256 matches your source)
You: "Everything works!"
```

## The Key Insight

**You don't need CI/CD to prevent this bug.**

**You need deployment invariants.**

The deploy script is a **guardrail**, not a pipeline. It prevents you from deploying the wrong thing, even if you forget to check manually.

## What This Doesn't Do

This system does NOT:
- Run tests (that's separate)
- Deploy to multiple servers (single-node only)
- Integrate with CI/CD (local-only)
- Handle rollbacks (manual only)

**It only guarantees: if the binary hash didn't change, the service doesn't restart.**

## Summary

**The invariant:** Binary hash must change for service to restart.

**The enforcement:** Deploy script checks hash before restart.

**The proof:** Service logs its own hash on startup.

**The result:** You can never debug the wrong binary again.

This is **DevOps hygiene**, not CI/CD. It's the foundation that makes everything else possible.
