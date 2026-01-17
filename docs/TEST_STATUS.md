# Backend Self-Test Status

## Current Status

**Test Structure:** ✅ Complete
**Test Vectors:** ⚠️ From failed verification attempt (test will fail until updated)

## The Lock

The `VerificationSelfTest` is the **"you broke App Attest" alarm**.

**Rule:** If this test fails, stop everything. No debating. No vibes.

## To Make Test Pass

1. **Fix frontend clientDataHash lifecycle bug** (attest vs. assert mismatch)
2. **Get successful end-to-end verification**
3. **Extract vectors from `/tmp/appattest/` artifacts:**
   ```bash
   latest=$(ls -t /tmp/appattest/*_pubkey.x963 | head -1 | sed 's/_pubkey.x963//')
   base64 -w 0 "${latest}_pubkey.x963"
   base64 -w 0 "${latest}_message.bin" | head -c <N>  # authenticatorData
   base64 -w 0 "${latest}_message.bin" | tail -c 32   # clientDataHash
   base64 -w 0 "${latest}_signature.der"
   ```
4. **Update `VerificationSelfTest.swift` with new vectors**
5. **Run:** `swift test --filter VerificationSelfTest`
6. **Test passes** → Commit immediately

## Once Test Passes

- ✅ Backend is proven correct
- ✅ Test becomes permanent regression test
- ✅ Any future failure = immediate alarm
- ✅ Commit locks in the fix forever

## Current Vectors

Vectors in test are from failed verification attempt (2026-01-17 10:38:49).
These will cause test to fail, which is correct behavior.

**Next:** Update with vectors from successful verification.
