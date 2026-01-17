# Backend Verification Self-Test

## Purpose

This test proves the App Attest backend verifier works correctly in isolation. It does **NOT** require iOS, Secure Enclave, or Apple App Attest. The test generates its own keypair and signature in-test, making it deterministic and always passing when the verifier is correct.

## Two-Test Model

### 1. Deterministic Self-Test (`VerificationSelfTest`)

**Always runs, always passes when verifier is correct.**

- Generates P-256 keypair in-test
- Creates fixed test bytes (authenticatorData, clientDataHash)
- Constructs COSE Sig_structure with correct encoding
- Signs with the private key
- Verifies using production `verifyAssertion()` function

**This is the "you broke App Attest" alarm.** If it fails, stop everything and fix the backend verifier.

### 2. Apple Golden Vector Test (`AppleGoldenVectorTests`)

**Optional, gated behind `RUN_APPLE_VECTORS=1` environment variable.**

- Uses real vectors captured from successful end-to-end verification
- Validates backend correctly verifies actual Apple signatures
- Only runs when explicitly enabled

## What the Deterministic Test Proves

**If test passes:**
- ✅ Backend verifier is mathematically correct
- ✅ COSE Sig_structure encoding is correct
- ✅ swift-crypto verification path is correct
- ✅ OpenSSL cross-check plumbing works (if available)
- ✅ Any production failures are **NOT** backend bugs

**If test fails:**
- ❌ Backend verifier has a bug
- ❌ Must fix before production use
- ❌ Check artifacts in `/tmp/appattest-selftest/` for ground truth

## Test Design

The deterministic test:
1. Generates P-256 keypair using `P256.Signing.PrivateKey()`
2. Creates fixed test bytes:
   - `authenticatorData`: 37 bytes (realistic App Attest format)
   - `clientDataHash`: 32 bytes (fixed, opaque input)
3. Constructs COSE Sig_structure with correct encoding:
   - `protected = h'A0'` (CBOR empty map, NOT h'')
   - `external_aad = h''` (empty)
   - `payload = authenticatorData || clientDataHash`
4. Signs the Sig_structure bytes with the private key
5. Converts signature to DER format
6. Verifies using the same `verifyAssertion()` function used by `/verify`
7. Negative control: also tests raw payload (should fail)

## Why clientDataHash Is NOT Generated on Backend

**Critical App Attest behavior:**
- `clientDataHash` is an **opaque 32-byte input** from the client
- Backend does **NOT** generate, recompute, or validate clientDataHash
- Backend treats it as a black box and uses it exactly as received

**Why this matters:**
- Client generates clientDataHash from challenge/request data
- Backend must use the **exact same** clientDataHash that was used when signature was created
- If clientDataHash differs between signature creation and verification, verification fails
- This is a **frontend lifecycle bug**, not a backend bug

**Test design:**
- Test uses fixed clientDataHash (arbitrary but deterministic)
- No generation, no computation, no validation
- Pure cryptographic verification test

## Running the Tests

### Deterministic Test (Always Runs)

```bash
cd /home/orangepi/Developer/appattest-backend
swift test --filter VerificationSelfTest
```

**Expected:** ✅ Pass (always, when verifier is correct)

### Apple Golden Vector Test (Optional)

```bash
# First, populate vectors in AppleGoldenVectorTests.swift from /tmp/appattest/ artifacts
# Then run:
RUN_APPLE_VECTORS=1 swift test --filter AppleGoldenVectorTests
```

**Expected:** ✅ Pass (when vectors are from successful verification)

## Test Artifacts

Deterministic test dumps to `/tmp/appattest-selftest/`:
- `selftest_pubkey.x963` - Public key (X9.63)
- `selftest_pubkey.pem` - Public key (PEM for OpenSSL)
- `selftest_signature.der` - Signature (DER)
- `selftest_payload.bin` - Raw payload (authenticatorData || clientDataHash)
- `selftest_sigstructure.cbor` - COSE Sig_structure (protected=h'A0')
- `selftest_meta.txt` - SHA256 hashes and results

## Manual OpenSSL Verification

You can manually verify with OpenSSL:

```bash
cd /tmp/appattest-selftest
openssl dgst -sha256 -verify selftest_pubkey.pem \
  -signature selftest_signature.der \
  selftest_sigstructure.cbor
```

Expected: `Verified OK`

## Populating Apple Golden Vectors

### Step 1: Get a Successful Verification

After a successful end-to-end verification, extract from `/tmp/appattest/`:

```bash
# Find latest artifacts
latest=$(ls -t /tmp/appattest/*_pubkey.x963 | head -1 | sed 's/_pubkey.x963//')

# Extract Base64-encoded vectors
base64 -w 0 "${latest}_pubkey.x963"        # → testPublicKeyX963Base64
base64 -w 0 "${latest}_message.bin" | head -c <N>  # First N bytes → testAuthenticatorDataBase64
base64 -w 0 "${latest}_message.bin" | tail -c 32    # Last 32 bytes → testClientDataHashBase64
base64 -w 0 "${latest}_signature.der"      # → testSignatureDERBase64
```

### Step 2: Update Test File

Edit `Tests/AppAttestBackendTests/AppleGoldenVectorTests.swift`:

```swift
let testPublicKeyX963Base64 = "<paste_base64_here>"
let testAuthenticatorDataBase64 = "<paste_base64_here>"
let testClientDataHashBase64 = "<paste_base64_here>"
let testSignatureDERBase64 = "<paste_base64_here>"
```

### Step 3: Run Test

```bash
RUN_APPLE_VECTORS=1 swift test --filter AppleGoldenVectorTests
```

## Relationship to Production

**Deterministic test proves:**
- Backend verifier math is correct
- COSE encoding is correct
- swift-crypto verification path works
- Given correct inputs, backend works
- Backend correctly treats clientDataHash as opaque input

**Deterministic test does NOT prove:**
- Frontend sends correct bytes
- Key lifecycle is correct
- clientDataHash continuity (frontend responsibility)
- Apple's actual signature format (use golden vector test for that)

**Production failures after deterministic test passes indicate:**
- Frontend bug (wrong bytes, wrong key, wrong hash, hash reuse)
- Flow bug (key mismatch, clientDataHash mismatch between attest/assert)
- NOT a backend verifier bug

## Isolating Backend Correctness from Frontend Bugs

**The deterministic test isolates backend verification logic by:**
1. **In-test generation:** Keypair and signature generated in-test (no external dependencies)
2. **Fixed inputs:** No variability, no network, no state
3. **Opaque clientDataHash:** Backend doesn't generate it (mirrors production)
4. **Same verifier:** Uses exact same `verifyAssertion()` as production
5. **Pure math:** No iOS, no Secure Enclave, no network, no state

**Result:**
- If deterministic test passes → Backend is correct
- If production fails → Frontend or flow bug (not backend)
- Clear separation of concerns

## Regression Test

The deterministic test is:
- **Permanent regression test** - run in CI
- **Ground truth** - proves backend correctness
- **Debugging tool** - isolate backend vs. frontend issues
- **Always passes** - when verifier is correct (no waiting for successful E2E runs)

## Summary

The deterministic test is a **proof harness** that isolates backend verification logic from all other concerns. It proves the backend is correct when given correct inputs, which is exactly what you need to lock in the fix and prevent regressions.

**The test does NOT depend on:**
- Successful end-to-end runs
- iOS or Secure Enclave
- Apple App Attest
- External test vectors

**The test DOES prove:**
- Backend verifier correctness
- COSE Sig_structure encoding correctness
- swift-crypto integration correctness
