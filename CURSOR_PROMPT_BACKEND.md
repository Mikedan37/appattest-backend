# Cursor Prompt: Orange Pi Backend (Run + Expose + Verify API)

**Purpose:**
Run the existing backend on the Orange Pi, expose it on the network, and verify `/health` and `/app-attest/verify` without changing validator or decoder code.

---

## Prompt

You are operating inside an existing Swift Vapor backend on Linux (Orange Pi).

The architecture is FINAL and MUST NOT change.

**Do NOT:**
- Refactor
- Optimize
- Rename types
- Change validator or decoder logic
- Add new endpoints
- Add retries or heuristics

Your task is strictly operational.

**Goals:**
1. Build the backend in release mode
2. Run it so it stays alive after SSH disconnect
3. Expose it on the local network
4. Verify the API works via curl

**Constraints:**
- The validator is an internal library function only
- The decoder reconstructs Sig_structure server-side
- Public keys never leave the server
- The backend listens on port 8080
- The backend MUST bind to 0.0.0.0, not 127.0.0.1

**Steps you must perform:**

### 1. Build the backend:

```bash
swift build -c release
```

### 2. Run it persistently (nohup or tmux is acceptable):

```bash
nohup swift run -c release AppAttestBackend > /tmp/appattest-backend.log 2>&1 &
```

### 3. Confirm the process is running:

```bash
ps aux | grep AppAttestBackend | grep -v grep
```

### 4. Confirm health endpoint locally:

```bash
curl http://127.0.0.1:8080/health
```

### 5. Confirm health endpoint from the network:

```bash
curl http://<ORANGE_PI_IP>:8080/health
```

**Expected response:**
```json
{"status":"ok"}
```

### 6. Verify `/app-attest/verify` rejects invalid input:

```bash
curl -X POST http://<ORANGE_PI_IP>:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:**
- HTTP 400 or rejection with reason
- No crashes
- No key leakage
- No validator output exposed

**If any step fails:**
- Report the exact command and output
- Do NOT modify core logic to "fix" it

**When all steps pass:**
- Stop
- Do not improve anything

---

## Notes

- Replace `<ORANGE_PI_IP>` with actual IP (e.g., `10.0.0.108`)
- Check firewall if network access fails: `sudo ufw allow 8080`
- View logs: `tail -f /tmp/appattest-backend.log`
- Stop service: `pkill -f AppAttestBackend`
