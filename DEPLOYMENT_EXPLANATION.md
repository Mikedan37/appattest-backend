# Deployment System

The deployment system enforces invariants that prevent running a binary that doesn't match the source code.

## Deployment Invariants

The deployment system enforces these rules:

1. **Build must succeed** - If `swift build` fails, service does not restart
2. **Binary must exist** - If build claims success but no binary exists, deployment aborts
3. **Binary hash must change** - If hash unchanged, service does not restart
4. **Service logs binary identity** - Every startup logs exe_path, SHA256, timestamp
5. **No silent failures** - Any invariant violation aborts loudly

## Deploy Script Flow

The deploy script (`scripts/deploy.sh`) performs these steps:

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

If any step fails, the script aborts and the service remains untouched.

## Binary Identity Logging

The backend logs binary identity on every startup:

```
CANARY routes configured
  exe_path: /home/orangepi/Developer/appattest-backend/.build/.../AppAttestBackend
  binary_sha256: <64-char hex>
  binary_timestamp: <ISO8601>
  binary_size_bytes: <size>
  process_start_time: <ISO8601>
```

## Usage

### Normal Deployment

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/deploy.sh
```

The script builds if needed, only restarts if binary changed, and logs all operations.

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

If hashes match, the running binary matches the source code.

## Systemd Configuration

The systemd service uses a wrapper script (`scripts/orangepi_run.sh`) that:
- Verifies binary exists before starting
- Does not build (build is manual via deploy script)
- Executes the binary directly

This ensures systemd never runs a stale or missing binary.

## Troubleshooting

### "Binary hash unchanged"

The code has not changed, or the build did not rebuild.

**Solution:** If restart is needed, delete `.deployed_binary_hash` and run deploy script again.

### "Build failed"

Check build output for errors. The deploy script shows the last 30 lines.

**Solution:** Fix compilation errors, then run deploy script again.

### "Service not running after restart"

Check service status:
```bash
sudo systemctl status appattest-backend
```

**Solution:** Check logs for startup errors. The deploy script shows service status.

### "Binary identity missing in logs"

The binary could not be read at startup (permissions issue).

**Solution:** Check file permissions on the binary. The service must be able to read its own executable.

### Build succeeded but deploy stopped at "sudo: a password is required"

The build finished. The new binary exists with a new hash. The deploy script stopped because it requires `sudo` to restart the service, and `sudo` could not read a password (non-interactive or IDE-run).

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

Hashes should match. If they don't, stop and fix.

## Summary

**The invariant:** If the binary hash did not change, the service does not restart.

**The enforcement:** Deploy script checks hash before restart.

**The proof:** Service logs its own hash on startup.

**The result:** The running binary matches the source code.
