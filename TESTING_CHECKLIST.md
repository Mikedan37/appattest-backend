# Testing Checklist

Three-layer validation process. No vibes, no philosophy.

## 1. Prove the code does what it says (local, deterministic)

```bash
swift test
```

**Expected:**
- All tests pass
- No skipped tests
- No network access
- No flakiness

**If this fails:** Stop. Fix the test or the code.

**This proves:**
- Decoder works
- Byte reconstruction is correct
- Signature verification is correct
- Non-guarantees are real and enforced

---

## 2. Prove the service runs and responds correctly (process-level)

**Build and run:**
```bash
swift build -c release
swift run -c release AppAttestBackend
```

**In another terminal:**
```bash
curl http://127.0.0.1:8080/health
```

**Expected:**
```json
{"status":"ok"}
```

**If this fails:**
- The service isn't running
- Or it crashed on startup
- Or routing is broken

**This proves:**
- Binary boots
- Routing works
- No crypto is triggered accidentally

---

## 3. Prove crypto behavior end-to-end (the real test)

### Step A: Generate real App Attest data (iOS app)

From an iOS test app:
1. Generate App Attest key
2. Perform attestation
3. Store:
   - `keyID`
   - `attestationObject`
   - `clientDataHash`

**Send to backend:**
```bash
curl -X POST http://127.0.0.1:8080/app-attest/register \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "...",
    "attestationObject": "...",
    "clientDataHash": "..."
  }'
```

**Expected:**
```json
{"status":"registered"}
```

**If this fails:**
- Decoder bug
- Bad base64
- Wrong attestation format

**Do not continue until this succeeds.**

---

### Step B: Verify a real assertion

From the same iOS app:
1. Generate an assertion using the same key
2. Capture:
   - `assertionObject`
   - `clientDataHash`

**Send:**
```bash
curl -X POST http://127.0.0.1:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "...",
    "assertionObject": "...",
    "clientDataHash": "..."
  }'
```

**Expected:**
```json
{"status":"verified"}
```

**This proves:**
- Correct byte sequence
- Correct key
- Correct ES256 verification
- No double-hashing
- No WebAuthn cargo cult

---

### Step C: Prove it fails when it should

**Flip one byte anywhere.**

Examples:
- Change one character in `clientDataHash`
- Change one byte in `assertionObject`
- Use a different `keyID`

**Send again.**

**Expected:**
```json
{"status":"rejected"}
```

**If it ever returns `verified` here, you have a bug. Period.**

---

## 4. Operational sanity (optional, fast)

**Restart the service:**
```bash
# ctrl+c
swift run -c release AppAttestBackend
```

**Now try verifying without re-registering.**

**Expected:**
```json
{"status":"rejected","reason":"public key not found"}
```

**This proves:**
- RAM-backed storage is real
- No hidden persistence
- No state leakage

---

## When you stop testing

You stop when all of these are true:
- ✅ Tests pass
- ✅ Health endpoint responds
- ✅ Real assertion verifies
- ✅ One-byte tamper fails
- ✅ Restart wipes keys

At that point, the system is closed.

Anything else is:
- Monitoring
- Policy
- Product decisions
- Someone else's problem

---

## Answer to "How do you know this works?"

Not prose.

The answer is:
1. `swift test`
2. One real assertion
3. One flipped byte

That's it.
