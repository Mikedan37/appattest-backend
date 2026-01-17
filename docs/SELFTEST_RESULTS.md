# Backend Verification Self-Test Results

## Purpose

This document records the results of the backend-only self-test (`VerificationSelfTest`), which proves the backend verifier works correctly in isolation using fixed test vectors.

## Test Design

The self-test:
1. Uses hardcoded test vectors (key, signature, authenticatorData, clientDataHash)
2. Constructs all 3 verification candidates:
   - Raw payload: `authenticatorData || clientDataHash`
   - COSE Sig_structure with `protected = h''` (truly empty)
   - COSE Sig_structure with `protected = h'A0'` (CBOR empty map - correct COSE encoding)
3. Verifies each candidate with:
   - swift-crypto (backend's primary verifier)
   - OpenSSL (independent cross-check)
4. Dumps all artifacts to `/tmp/appattest-selftest/` for manual inspection
5. Asserts at least one candidate passes (proving backend is correct)

## Current Status

**Test vectors:** Placeholder (will fail until real vectors are provided)

**Why placeholders:**
- Test vectors must come from a known-good end-to-end verification
- Once we have a successful verification, extract bytes from `/tmp/appattest/` artifacts
- Update test with real vectors to prove backend correctness

## How to Populate Real Test Vectors

1. **Run a successful end-to-end verification:**
   ```bash
   # After iOS client successfully verifies
   ls -t /tmp/appattest/*_pubkey.x963 | head -1
   ls -t /tmp/appattest/*_signature.der | head -1
   ls -t /tmp/appattest/*_message.bin | head -1
   ```

2. **Extract bytes:**
   - `pubkey.x963` → `testPublicKeyX963` (65 bytes, starts with 0x04)
   - `signature.der` → `testSignatureDER` (71-72 bytes, starts with 0x30)
   - `message.bin` → split into `testAuthenticatorData` (first 37 bytes) and `testClientDataHash` (last 32 bytes)

3. **Update test:**
   - Replace placeholder vectors in `VerificationSelfTest.swift`
   - Run: `swift test --filter VerificationSelfTest`

4. **Expected result:**
   - At least one candidate passes (likely `sigstruct_a0`)
   - Backend is proven correct
   - Test can be used as regression test

## Interpretation

**If test passes:**
- Backend verifier is correct
- COSE encoding is correct
- Any production failures are due to:
  - Frontend sending wrong bytes
  - Key mismatch
  - Signature extraction issue
  - NOT a backend verifier bug

**If test fails with real vectors:**
- Backend verifier has a bug
- Must fix before production use
- Check artifacts for ground truth

## Artifacts

Test dumps to `/tmp/appattest-selftest/`:
- `selftest_pubkey.x963` - Public key (X9.63)
- `selftest_pubkey.pem` - Public key (PEM for OpenSSL)
- `selftest_signature.der` - Signature (DER)
- `selftest_raw_payload.bin` - Raw payload candidate
- `selftest_sigstruct_empty.cbor` - Sig_structure with protected=h''
- `selftest_sigstruct_a0.cbor` - Sig_structure with protected=h'A0'
- `selftest_meta.txt` - SHA256 hashes and verification results

## Running the Test

```bash
cd /home/orangepi/Developer/appattest-backend
swift test --filter VerificationSelfTest
```

## Next Steps

1. Wait for successful end-to-end verification
2. Extract real test vectors from artifacts
3. Update test with real vectors
4. Test passes → backend is proven correct
5. Use test as regression test going forward
