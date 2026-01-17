# App Attest Verification Fix Summary

## Problem

App Attest assertion verification was failing with:
```json
{"status":"rejected","reason":"Signature did not verify under the supplied public key"}
```

Even though all byte-level hashes matched and all components were correct.

## Root Cause

The backend was verifying over **raw concatenation** (`authenticatorData || clientDataHash`) instead of the **COSE Sig_structure** that Apple actually signs.

## Solution

Updated the backend to verify over COSE Sig_structure:

1. **Construct COSE Sig_structure:**
   ```swift
   Sig_structure = [
     "Signature1",                    // text string
     protected_headers,                // empty bstr
     external_aad,                     // empty bstr
     authenticatorData || clientDataHash  // bstr
   ]
   ```

2. **Verify over Sig_structure:**
   - CBOR-encode the Sig_structure array
   - Pass the CBOR-encoded bytes to the verifier
   - swift-crypto hashes internally: `SHA256(CBOR.encode(Sig_structure))`

## Changes Made

### Code Changes (`main.swift`)

1. **Message Construction:**
   - Changed from raw concatenation to COSE Sig_structure
   - Added `constructCOSESigStructure()` call
   - Verify over `messageToVerify` (Sig_structure) instead of `payload` (raw)

2. **Verification Matrix:**
   - Tests both Sig_structure (primary) and raw payload (diagnostic)
   - Logs results for both swift-crypto and OpenSSL
   - Interpretation logic identifies which bytes Apple signed

3. **Forensic Dumps:**
   - Dumps both `message.bin` (raw payload) and `sigstructure.cbor` (COSE structure)
   - Allows manual OpenSSL verification to confirm which one works

### Documentation Changes

1. **`docs/COSE_SIG_STRUCTURE_FIX.md`:**
   - Complete fix documentation
   - Explains the problem, solution, and implementation

2. **`docs/APP_ATTEST_ASSERTION_SIGNED_BYTES.md`:**
   - Updated to reflect COSE Sig_structure requirement
   - Corrected previous incorrect assumption about raw concatenation

## Testing

After deploying the fix:

1. **Run Register → Verify flow:**
   - Generate key on iOS
   - Attest and register
   - Generate assertion and verify

2. **Check logs:**
   ```bash
   sudo journalctl -u appattest-backend --since "2 minutes ago" | grep VERIFY_MATRIX
   ```

3. **Expected result:**
   - `swiftcrypto_sigstructure: true`
   - `openssl_sigstructure: true`
   - `swiftcrypto_rawpayload: false` (diagnostic)
   - `openssl_rawpayload: false` (diagnostic)
   - `interpretation: "✓ Both verify over Sig_structure → correct implementation"`

4. **Verify response:**
   ```json
   {"status":"verified"}
   ```

## Verification Matrix Interpretation

The `VERIFY_MATRIX` log shows:

- **If `openssl_sigstructure: true`** → Apple signs over Sig_structure (correct)
- **If `openssl_rawpayload: true`** → Apple signs over raw payload (unexpected)
- **If both false** → Key/signature mismatch or extraction bug

## Files Modified

- `Sources/AppAttestBackend/main.swift` - Core verification logic
- `docs/COSE_SIG_STRUCTURE_FIX.md` - Fix documentation (new)
- `docs/APP_ATTEST_ASSERTION_SIGNED_BYTES.md` - Updated signed bytes documentation

## Next Steps

1. Test with real iOS client
2. Verify `VERIFY_MATRIX` shows Sig_structure verification succeeds
3. Confirm `/app-attest/verify` returns `{"status":"verified"}`

## Reference

- COSE Sig_structure: RFC 8152 Section 4.4
- App Attest uses Sig_structure format for assertion signatures
- The assertion object is a CBOR map, but the signature is over a Sig_structure
