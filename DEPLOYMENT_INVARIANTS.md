# Deployment Invariants

This document describes the deployment safety system that prevents "wrong binary running" bugs.

## Problem Statement

Without deployment invariants, you can:
- Edit source code
- Run `swift build`
- See "build succeeded"
- Restart the service
- Debug logs from a different binary than the code you're reading

This is a **DevOps footgun**, not a coding bug.

## Solution: Hard Invariants

The deployment system enforces these rules:

1. **Build must succeed** - If `swift build` fails, service does NOT restart
2. **Binary must exist** - If build claims success but no binary exists, abort
3. **Binary hash must change** - If hash unchanged, service does NOT restart
4. **Service logs binary identity** - Every startup logs exe_path, SHA256, timestamp
5. **No silent failures** - Any invariant violation aborts loudly

## Components

### 1. Deploy Script (`scripts/deploy.sh`)

The deploy script enforces all invariants:

```bash
./scripts/deploy.sh
```

**What it does:**
1. Cleans `.build/` directory
2. Runs `swift build -c release --product AppAttestBackend`
3. Verifies binary exists and is executable
4. Computes binary SHA256
5. Compares to last deployed hash (stored in `.deployed_binary_hash`)
6. Only restarts service if hash changed
7. Saves new hash to `.deployed_binary_hash`
8. Verifies service is running after restart

**If any step fails, the script aborts and the service remains untouched.**

### 2. Binary Identity Logging

The backend logs binary identity on every startup:

```
CANARY routes configured
  exe_path: /home/orangepi/Developer/appattest-backend/.build/.../AppAttestBackend
  binary_sha256: <64-char hex>
  binary_timestamp: <ISO8601>
  binary_size_bytes: <size>
  process_start_time: <ISO8601>
```

**This proves which binary is actually running.**

### 3. Health Endpoint

`GET /health` returns binary identity (layer 2) and semantic invariants (layer 3):

```json
{
  "status": "ok",
  "buildSha256": "<64-char hex>",
  "buildTime": "<ISO8601>",
  "storageBackend": "RAM",
  "keyCount": 0,
  "clientDataHashCount": 0,
  "uptimeSeconds": 123.45,
  "lastVerifyRunIDSeen": null
}
```

**Binary identity (layer 2):** `buildSha256`, `buildTime` — pair with `.deployed_binary_hash` on the Pi. Mismatch ⇒ wrong binary.

**Semantic (layer 3):** `storageBackend`, `keyCount`, `clientDataHashCount`, `uptimeSeconds`, `lastVerifyRunIDSeen` — app-level contract sanity.

For the full three-layer status-from-Mac flow (systemd, binary identity, semantic), see **README § Remote observability (Status from Mac)**.

### 4. Hash Persistence

The last deployed binary hash is stored in:
- `.deployed_binary_hash` (git-ignored)

**This prevents unnecessary restarts when nothing changed.**

## Usage

### Normal Deployment

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/deploy.sh
```

The script will:
- Build if needed
- Only restart if binary changed
- Log everything

### Force Restart (Same Binary)

If you need to restart without rebuilding:

```bash
sudo systemctl restart appattest-backend
```

**Warning:** This bypasses the hash check. Only use if you know the binary is correct.

### Verify Running Binary

Check logs:
```bash
sudo journalctl -u appattest-backend -n 20 | grep "CANARY"
```

Check health endpoint:
```bash
curl http://localhost:8080/health
```

Compare hashes:
```bash
cat .deployed_binary_hash
sha256sum .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

## Why This Prevents "Wrong Binary Running"

**Before (broken):**
1. Edit code
2. `swift build` (fails silently or builds wrong target)
3. `sudo systemctl restart` (restarts old binary)
4. Debug logs from wrong binary
5. Confusion and wasted time

**After (fixed):**
1. Edit code
2. `./scripts/deploy.sh`
3. Script verifies build succeeded
4. Script verifies binary exists
5. Script checks hash changed
6. Only then restarts service
7. Service logs its own hash on startup
8. You can verify logs match binary

**If any step fails, you know immediately and the service doesn't restart.**

## Systemd Configuration

The systemd service uses a wrapper script (`scripts/orangepi_run.sh`) that:
- Verifies binary exists before starting
- Does NOT build (build is manual via deploy script)
- Executes the binary directly

**This ensures systemd never runs a stale or missing binary.**

## Troubleshooting

### "Binary hash unchanged"

This means you haven't changed the code, or the build didn't actually rebuild.

**Solution:** If you want to restart anyway, delete `.deployed_binary_hash` and run deploy script again.

### "Build failed"

Check build output for errors. The deploy script will show the last 30 lines.

**Solution:** Fix compilation errors, then run deploy script again.

### "Service not running after restart"

Check service status:
```bash
sudo systemctl status appattest-backend
```

**Solution:** Check logs for startup errors. The deploy script will show service status.

### "Binary identity missing in logs"

This means the binary couldn't be read at startup (permissions issue?).

**Solution:** Check file permissions on the binary. The service should be able to read its own executable.

### Build succeeded but deploy stopped at "sudo: a password is required"

The build finished. The new binary exists with a new hash. The deploy script stopped on purpose because it won't restart the service without `sudo`, and `sudo` couldn't read a password (e.g. non‑interactive or IDE-run). This is correct behavior. Annoying, but correct.

**What actually happened:** `swift build` ✓, binary ✓, hash ✓, restart ✗ (sudo prompt). Nothing is broken. The binary is not wrong. This is not Swift being broken. ARM + Swift + crypto + release + systemd + sudo = character development.

**Option A (recommended):** Re-run deploy. It will not rebuild (incremental, nothing changed). It will restart and update the hash. Enter your sudo password when prompted.

```bash
cd /home/orangepi/Developer/appattest-backend
SKIP_CLEAN=1 ./scripts/deploy.sh
```

**Option B (manual):** Restart and verify yourself:

```bash
sudo systemctl restart appattest-backend
curl http://localhost:8080/health
sudo journalctl -u appattest-backend -n 10 | grep CANARY
```

Hashes should line up. If they don't, stop and fix.

**Optional, later:** To avoid prompts when running deploy from scripts or CI, add passwordless `sudo` for this service only. Not urgent.

## Future Improvements

- Add build timestamp to binary (compile-time constant)
- Add git commit hash to binary (compile-time constant)
- Add automated tests that verify binary identity matches source
- Add CI/CD integration that enforces these invariants

## Summary

**The invariant:** If the binary hash didn't change, the service must not restart.

**The enforcement:** Deploy script checks hash before restart.

**The proof:** Service logs its own hash on startup.

**The result:** You can never debug the wrong binary again.
