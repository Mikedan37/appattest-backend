# Build System

This appendix describes the build and deployment system.

## Deployment System

This project uses a deployment system with hard invariants to prevent "wrong binary running" bugs. The deploy script enforces:

1. **Build must succeed** - Service only restarts if build completes successfully
2. **Binary must exist** - Verifies binary exists and is executable after build
3. **Binary hash must change** - Service only restarts if binary actually changed
4. **Service logs binary identity** - Every startup logs `exe_path`, `binary_sha256`, `binary_timestamp`

## Deploying

**Always use the deploy script:**

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/deploy.sh
```

On ARM (e.g. Orange Pi), the link phase can take 5–15 minutes with no `swiftc` in `ps` — that's normal. Run `./scripts/link-heartbeat.sh` in another terminal to confirm the build is alive.

**Fast builds when testing:** `./scripts/build-fast.sh` (inner loop; 90% of the time) or `SKIP_CLEAN=1 ./scripts/deploy.sh` (outer loop). Full `./scripts/deploy.sh` is ceremony.

The script will:
- Clean build directory (skipped if `SKIP_CLEAN=1`)
- Build release binary (product-only, skips tests)
- Verify binary exists
- Compute SHA256 hash
- Compare to last deployed hash
- Only restart service if hash changed
- Log everything

**Never manually restart the service after editing code.** Use the deploy script.

## Verify Running Binary

After deployment, verify the binary matches your source:

```bash
# Check logs for binary identity
sudo journalctl -u appattest-backend -n 20 | grep "CANARY"

# Check health endpoint
curl http://localhost:8080/health

# Compare hashes
cat .deployed_binary_hash
sha256sum .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

The `CANARY` log entry includes:
- `exe_path` - Full path to running binary
- `binary_sha256` - SHA256 hash of the binary
- `binary_timestamp` - File modification time
- `binary_size_bytes` - File size

## Link Phase on ARM

On ARM platforms (e.g. Orange Pi), the Swift compiler link phase can take 5–15 minutes with no visible `swiftc` process. This is normal behavior.

**Why it appears stuck:**
- The linker (`ld`) is running, not `swiftc`
- No CPU activity visible in `ps` for `swiftc`
- Link phase is CPU-intensive and single-threaded

**How to confirm it's alive:**
- Run `./scripts/link-heartbeat.sh` in another terminal
- Check for `.build` directory updates
- Monitor disk I/O activity

**Tuning:**
- Use `build-fast.sh` for development (skips clean, faster iteration)
- Use `SKIP_CLEAN=1` to skip clean phase
- Full `deploy.sh` is for production deployments
