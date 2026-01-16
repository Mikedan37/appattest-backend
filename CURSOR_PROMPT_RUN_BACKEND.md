# Cursor Prompt: Run App Attest Backend on Orange Pi (Local Network Access)

## Context

You are on an Orange Pi (Linux, ARM64).
A Swift + Vapor backend already exists and builds successfully.
This backend exposes App Attest verification via HTTP.

The architecture is finalized.
You must only run and expose the backend.
Do not refactor, redesign, or add features.

---

## Goals

1. Build the backend in release mode
2. Run it as a long-lived process
3. Bind it to 0.0.0.0 so it's reachable from the local network
4. Verify the API is accessible from another device (iOS app / curl)
5. Stop once verified

---

## Non-Negotiable Rules

- Do NOT modify validator or decoder logic
- Do NOT expose the validator as a standalone service
- Do NOT add new endpoints
- Do NOT optimize or clean up code
- Do NOT silence warnings unless they break execution

This is infrastructure execution only.

---

## Step 1: Build (Release)

From the backend root directory:

```bash
swift build -c release
```

Do not interrupt the build.
First build on ARM + Vapor is slow. This is expected.

---

## Step 2: Run the Backend

Run the release binary using SwiftPM:

```bash
swift run -c release AppAttestBackend
```

OR, if an executable is produced:

```bash
.build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

The server must:
- Start without crashing
- Stay alive
- Log that it is listening on port 8080

---

## Step 3: Confirm Network Binding

Verify the server is listening on 0.0.0.0:8080, not 127.0.0.1.

If using Vapor, ensure this exists (do not redesign it):

```swift
app.http.server.configuration.hostname = "0.0.0.0"
app.http.server.configuration.port = 8080
```

If already present, do nothing.

---

## Step 4: Open Firewall (Temporary)

Allow local network access:

```bash
sudo ufw allow 8080
```

Or temporarily disable firewall for testing:

```bash
sudo ufw disable
```

---

## Step 5: Verify Locally on Orange Pi

```bash
curl http://127.0.0.1:8080/health
```

Expected response:

```json
{ "status": "ok" }
```

---

## Step 6: Verify From Another Device

From macOS or iOS device on the same network:

```bash
curl http://<ORANGE_PI_IP>:8080/health
```

If this works, the backend is correctly exposed.

---

## Step 7: Keep It Running

For testing, run in background:

```bash
nohup swift run -c release AppAttestBackend > /tmp/appattest-backend.log 2>&1 &
```

Confirm it's running:

```bash
ps aux | grep AppAttestBackend | grep -v grep
```

---

## Stop Condition

Once the following are true:
- `/health` responds locally
- `/health` responds from another device
- Server stays running

**STOP.**

Do not:
- Add systemd services
- Add Docker
- Add monitoring
- "Improve" anything

Those are deployment concerns, not testing concerns.

---

## Final Output Required

Print:
- The Orange Pi IP address
- Confirmation that `/health` works from another device

Then stop.

---

**That's it.**
If Cursor tries to "help" beyond this, reject it.
You're running a backend, not inventing a new religion.
