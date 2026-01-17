# COSE Sig_structure Fix: App Attest Assertion Verification

## Problem

App Attest assertion verification was failing with:
```json
{"status":"rejected","reason":"Signature did not verify under the supplied public key"}
```

Even though:
- keyID matched between register and verify
- Public key matched
- clientDataHash matched
- All byte-level hashes matched logs
- OpenSSL verification failed on both raw payload and Sig_structure

## Root Cause

The backend was verifying over **raw concatenation** (`authenticatorData || clientDataHash`) instead of the **COSE Sig_structure** that Apple actually signs.

## Correct Signed Bytes

App Attest assertions are signed over a **COSE Sig_structure** (CBOR array), not raw concatenation:

```
Sig_structure = [
  "Signature1",                    // text string (item 0)
  protected : bstr,                // byte string (item 1) - empty h'' for App Attest, NOT {}
  external_aad : bstr,             // byte string (item 2) - empty h'' for App Attest, NOT {}
  payload : bstr                   // byte string (item 3) - authenticatorData || clientDataHash
]
```

**CRITICAL:** `protected` and `external_aad are **byte strings (bstr)**, NOT maps.
- Empty protected headers = `h''` (empty byte string), NOT `{}` (empty map)
- Empty external_aad = `h''` (empty byte string), NOT `{}` (empty map)

The signature is computed over:
```
SHA256(CBOR.encode(Sig_structure))
```

**NOT** over:
```
SHA256(authenticatorData || clientDataHash)
```

## Fix

1. **Construct COSE Sig_structure:**
   - CBOR array with 4 items (starts with `0x84`)
   - Item 0: text string "Signature1"
   - Item 1: **byte string** (bstr) for protected headers - empty `h''` for App Attest, **NOT** `{}`
   - Item 2: **byte string** (bstr) for external_aad - empty `h''` for App Attest, **NOT** `{}`
   - Item 3: **byte string** (bstr) containing `authenticatorData || clientDataHash`

2. **Verify over Sig_structure:**
   - Pass the CBOR-encoded Sig_structure bytes to the verifier
   - swift-crypto's `isValidSignature(_:for: Data)` hashes the Data internally

3. **Forensic artifacts:**
   - Dump both `message.bin` (raw payload) and `sigstructure.cbor` (COSE structure)
   - Verify with OpenSSL on both to confirm which one Apple actually signed

## Implementation

The fix is in `main.swift`:

```swift
// Construct payload (authenticatorData || clientDataHash)
let payload = authenticatorData + clientDataHash

// Construct COSE Sig_structure
// CRITICAL: protected and externalAAD are Data (byte strings), NOT maps
let protected = Data() // Empty → encoded as empty bstr h'', NOT {}
let externalAAD = Data() // Empty → encoded as empty bstr h'', NOT {}
let sigStructureBytes = constructCOSESigStructure(
    protected: protected,    // bstr, not map
    externalAAD: externalAAD, // bstr, not map
    payload: payload
)

// Verify: Sig_structure must start with 0x84 (array of 4)
guard sigStructureBytes.first == 0x84 else {
    // CBOR encoding error
}

// Verify over Sig_structure (not raw payload)
let isValid = verifyAssertion(
    publicKeyX963: publicKeyData,
    signatureDER: signatureDER,
    message: sigStructureBytes  // ← Sig_structure CBOR bytes, not raw payload
)
```

## Verification Matrix

The backend now tests both candidates and logs results:

- `swiftcrypto_sigstructure`: Verification over Sig_structure (should pass)
- `swiftcrypto_rawpayload`: Verification over raw payload (should fail)
- `openssl_sigstructure`: OpenSSL verification over Sig_structure
- `openssl_rawpayload`: OpenSSL verification over raw payload

**Expected result:** `openssl_sigstructure: true` and `swiftcrypto_sigstructure: true`

## Why This Matters

If you verify over raw concatenation when Apple signed over Sig_structure:
- All components are correct (key, signature, payload)
- But verification fails because you're verifying the wrong bytes
- This is a silent failure that's hard to diagnose without forensic artifacts

## Detection

Check `VERIFY_MATRIX` log:
- If `openssl_sigstructure: true` → Apple signs over Sig_structure
- If `openssl_rawpayload: true` → Apple signs over raw payload
- If both false → Key/signature mismatch or extraction bug

**Verification checklist:**
- `VERIFY_MATRIX openssl_sigstructure == true` and `swiftcrypto_sigstructure == true`
- `openssl_rawpayload == false` (expected if Sig_structure is correct)
- Dumped artifact `sigstructure.cbor` starts with `0x84` (CBOR array of 4)
- Protected and external_aad inside CBOR are byte strings (bstr), not maps

**Common mistake:**
- Using `{}` (empty map) for protected/external_aad instead of `h''` (empty byte string)
- This causes CBOR encoding to be wrong and verification to fail

## Reference

- COSE Sig_structure: RFC 8152 Section 4.4
- App Attest uses Sig_structure format, not raw concatenation
- The assertion object is a CBOR map, but the signature is over a Sig_structure
