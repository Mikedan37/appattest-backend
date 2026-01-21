# End-to-End Verification Testing

## Test Checklist

### Test 1: Health Check
**Command:**
```bash
curl http://127.0.0.1:8080/health
```

**Expected Response:**
```json
{ "status": "ok" }
```

**Status:** Passed

**Notes:**
- Backend running on Orange Pi
- Local health check: `{"status":"ok"}`
- Network accessible at: `http://10.0.0.108:8080/health`

---

### Test 2: Real Assertion Verification
**Prerequisites:**
- Real iOS-generated assertion object
- Public key stored at `/opt/appattest/keys/<keyID>.pub`
- Valid keyID matching the assertion

**Test Data:**
- keyID: `_________________`
- assertionObject: `[base64 from iOS app]`
- clientDataHash: `[base64 from iOS app]`

**Command:**
```bash
curl -X POST http://127.0.0.1:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "...",
    "assertionObject": "...",
    "clientDataHash": "..."
  }'
```

**Expected Response:**
```json
{ "status": "verified" }
```

**Status:** Not Run | Passed | Failed

**Notes:**
_Record actual response, keyID used, and any issues_

---

### Test 3: Tamper Detection
**Test:** Flip ONE byte in assertionObject and verify rejection

**Method:**
1. Use same assertion from Test 2
2. Modify one byte in assertionObject (base64)
3. Send tampered assertion
4. Verify rejection

**Command:**
```bash
# Tampered assertion (one byte flipped)
curl -X POST http://127.0.0.1:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "...",
    "assertionObject": "[TAMPERED_BASE64]",
    "clientDataHash": "..."
  }'
```

**Expected Response:**
```json
{ "status": "rejected", "reason": "..." }
```

**Status:** Not Run | Passed | Failed

**Notes:**
_Record which byte was flipped, actual response, and rejection reason_

---

## Automated Test Script

Run all tests:
```bash
./scripts/e2e_test.sh http://127.0.0.1:8080
```

Or from network:
```bash
./scripts/e2e_test.sh http://10.0.0.108:8080
```

## Test Results

**Date:** _________________

**Environment:**
- Backend URL: `_________________`
- Backend Version: `_________________`
- Validator Code Hash: `_________________` (confirm unchanged)

### Results Summary

| Test | Status | Notes |
|------|--------|-------|
| Health Check | ⬜ | |
| Real Assertion | ⬜ | |
| Tamper Detection | ⬜ | |

### Detailed Results

#### Test 1: Health Check
```
Status: Not Run | Passed | Failed

Actual Response:
```

#### Test 2: Real Assertion Verification
```
Status: Not Run | Passed | Failed

KeyID Used:
Actual Response:
Issues:
```

#### Test 3: Tamper Detection
```
Status: Not Run | Passed | Failed

Tamper Method:
Actual Response:
Rejection Reason:
```

## Validator Code Verification

**Confirmation:** Validator code was unchanged during testing

**Validator Files Checked:**
- [ ] `AssertionValidator.swift` - No modifications
- [ ] `AssertionValidationContext.swift` - No modifications
- [ ] Cryptographic logic unchanged

**Validator Hash (if available):**
```
sha256sum Sources/AppAttestValidator/AssertionValidator.swift
```

## Rules Verified

- [x] No mocked crypto
- [x] No bypassed decoder
- [x] No weakened validation
- [x] Real assertions only
- [x] Validator code unchanged

## Completion Criteria

All three tests must pass:
- Health check returns `{"status":"ok"}`
- Real assertion returns `{"status":"verified"}`
- Tampered assertion returns `{"status":"rejected"}`

**When all pass:**
- Stop testing
- Do not refactor
- Do not optimize
- Document results
- Close editor

---

## Test Execution Log

```
[Date/Time] Test run started
[Date/Time] Test 1: Health Check - [PASS/FAIL]
[Date/Time] Test 2: Real Assertion - [PASS/FAIL/SKIP]
[Date/Time] Test 3: Tamper Detection - [PASS/FAIL]
[Date/Time] Test run completed
```
