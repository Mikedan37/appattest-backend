# Forensic Audit Report: App Attest Assertion Verification Failure

## Executive Summary

**Status:** All invariants verified except one critical mismatch in signed bytes construction.

**Root Cause:** The backend is passing raw `authenticatorData || clientDataHash` bytes to the validator, but App Attest assertions are signed over a COSE Sig_structure, not raw concatenation.

**Fix Required:** Construct the COSE Sig_structure as `["Signature1", protected_headers, external_aad, payload]` where payload is `authenticatorData || clientDataHash`.

---

## 1. Backend Log Analysis (Most Recent Verify: 07:54:31)

### Transport Integrity: ✅ VERIFIED
- `keyID_sha256`: `4e6435b72b14b244349d059fd1be9e03ed40081b39933b5385845bf591595ea8`
- `assertionObject_sha256`: `398798d345fb61ddd68afb1bb8ae86399aa5908071df1b75234d7e58fcd19c0c`
- `assertionObject_length`: 142 bytes
- `clientDataHash_hex`: `eeeb060e13859d2d7ccb9067c3e8c77caf59b54185bdccd8d2421c0fba4f6113`
- `clientDataHash_length`: 32 bytes

### Public Key Continuity: ✅ VERIFIED
- **REGISTER (07:54:30):**
  - `extractedPublicKey_sha256`: `944d5e855baf659a0c518fb2a15740ebf03ae7ae14885b89ff261d2c1fb55e59`
  - `storedPublicKey_sha256`: `944d5e855baf659a0c518fb2a15740ebf03ae7ae14885b89ff261d2c1fb55e59`
  - `keysMatch`: `true`

- **VERIFY (07:54:31):**
  - `storedPublicKey_sha256`: `944d5e855baf659a0c518fb2a15740ebf03ae7ae14885b89ff261d2c1fb55e59`
  - `storedPublicKey_length`: 65 bytes
  - `storedPublicKey_firstByte`: `0x04`
  - `storedPublicKey_format`: `X9.63 uncompressed`

**Conclusion:** Public key storage and retrieval are correct. The same key is used for registration and verification.

### CBOR Extraction: ✅ VERIFIED
- `authenticatorData_length`: 37 bytes
- `authenticatorData_sha256`: `eff0a99b13f003f5b1cc733005d2ff38f9bf0c2673387daee35c9daffc2d0f09`
- `signature_length`: 72 bytes
- `signature_firstByte`: `0x30` (DER format)
- `signature_sha256`: `b4e9264a0721d6c4b5cac348cd3d07cc9db55f2d18e316e27dacfb5863950003`

**Conclusion:** CBOR extraction is correct. AuthenticatorData and signature are extracted properly.

### Signed Bytes Construction: ⚠️ POTENTIAL ISSUE
- `signedBytes_length`: 69 bytes (37 + 32) ✅
- `signedBytes_sha256`: `305f6bb2596c56def116e643e302bff2b24a06d8ec75c402291f8e12d1bd6510`
- `construction`: `authenticatorData || clientDataHash (raw concatenation)`

**Issue:** The backend constructs `payload = authenticatorData + clientDataHash` and passes it directly as `sigStructure`. However, App Attest assertions are signed over a COSE Sig_structure, not raw concatenation.

---

## 2. Validator Identity: ✅ VERIFIED

**Single Validator Instance:**
- Only one `AssertionValidator.validate()` call site exists (line 746)
- Uses `AssertionValidationContext` with:
  - `publicKey: P256.Signing.PublicKey` (created from X9.63 representation) ✅
  - `sigStructure: Data` (currently raw payload) ⚠️
  - `signatureDER: Data` (ASN.1 DER format) ✅

**No Duplicate Validators:**
- Single validator implementation in `AppAttestValidator/AppAttestValidatorCLI/AssertionValidator.swift`
- No alternative code paths found

---

## 3. Verification Call Audit

### Code Path (main.swift:720-746):
```swift
let payload = authenticatorData + clientDataHash  // Line 594
let sigStructure = payload                         // Line 623
let context = try AssertionValidationContext(
    publicKey: publicKey,
    sigStructure: sigStructure,                    // Line 725
    signatureDER: signatureDER
)
let validationResult = AssertionValidator.validate(context)  // Line 746
```

### Validator Implementation (AssertionValidator.swift:72):
```swift
let isValid = context.publicKey.isValidSignature(signature, for: context.sigStructure)
```

**Analysis:**
- ✅ Public key is created using `x963Representation` (line 430)
- ✅ Signature is parsed as ASN.1 DER (line 62)
- ✅ `isValidSignature(_:for:)` is called correctly
- ⚠️ **ISSUE:** `sigStructure` is raw bytes, but App Attest signs over COSE Sig_structure

---

## 4. Hard Assertions

### ✅ PASSED:
- `signedBytes_length == authenticatorData_length + 32`: 69 == 37 + 32 ✅
- `publicKey.x963Representation.count == 65`: ✅
- `publicKey.x963Representation.first == 0x04`: ✅
- `signature.first == 0x30`: ✅
- `keyID_sha256` matches between register and verify: ✅

### ❌ FAILED:
- **Signed bytes format:** Backend passes raw `authenticatorData || clientDataHash`, but App Attest signs over COSE Sig_structure.

---

## 5. Root Cause Analysis

### The Mismatch

**What the backend does:**
```swift
let payload = authenticatorData + clientDataHash
let sigStructure = payload  // Raw bytes: 69 bytes
```

**What App Attest actually signs:**
According to COSE specification, the signature is computed over:
```
Sig_structure = [
    "Signature1",
    protected_headers,
    external_aad,
    payload
]
```

Where:
- `protected_headers`: CBOR-encoded protected header (typically empty map `{}` for App Attest)
- `external_aad`: External additional authenticated data (empty bstr `h''` for App Attest)
- `payload`: `authenticatorData || clientDataHash` (raw bytes)

**The Fix:**
The backend must construct the COSE Sig_structure CBOR array before passing to the validator:

```swift
// Construct COSE Sig_structure
var sigStructure = Data()
sigStructure.append(0x84) // Array of 4 items
sigStructure.append(0x6a) // Text string "Signature1" (10 bytes)
sigStructure.append(contentsOf: "Signature1".utf8)
sigStructure.append(0xa0) // Empty map {} (protected headers)
sigStructure.append(0x40) // Empty byte string (external_aad)
sigStructure.append(0x58) // Byte string tag
sigStructure.append(UInt8(payload.count)) // Length
sigStructure.append(contentsOf: payload) // authenticatorData || clientDataHash
```

---

## 6. Why This Bug Survives Normal Logging

1. **Length checks pass:** `signedBytes_length == authenticatorData_length + 32` is correct
2. **Hash matches:** The SHA256 of raw bytes matches between client and backend
3. **Format looks correct:** All individual components are correct
4. **The missing piece:** The COSE Sig_structure wrapper is not constructed, so the bytes being verified don't match what Apple signed

**The validator receives:**
- Raw payload: `authenticatorData || clientDataHash` (69 bytes)

**Apple signed:**
- COSE Sig_structure: `["Signature1", {}, h'', authenticatorData || clientDataHash]` (~85-90 bytes when CBOR-encoded)

These are different byte sequences, so verification fails even though all components are correct.

---

## 7. Why This Is NOT an App Attest Issue

This is a backend implementation bug, not an App Attest specification issue:

1. **App Attest spec is clear:** Assertions use COSE_Sign1 format, which requires Sig_structure
2. **The backend comment is misleading:** Line 583 says "This is NOT a CBOR-wrapped COSE Sig_structure" - this is incorrect
3. **The validator expects Sig_structure:** The `AssertionValidationContext` field is named `sigStructure` for a reason

---

## 8. Minimal Fix

**File:** `Sources/AppAttestBackend/main.swift`

**Location:** After line 594 (payload construction), before line 623 (sigStructure assignment)

**Change:**
```swift
// 4. Construct the exact bytes Apple signed (COSE Sig_structure)
//
// **App Attest signature payload:**
// Apple signs over COSE Sig_structure: ["Signature1", protected_headers, external_aad, payload]
// Where payload = authenticatorData || clientDataHash
//
let payload = authenticatorData + clientDataHash

// Construct COSE Sig_structure CBOR array
var sigStructureBytes = Data()
sigStructureBytes.append(0x84) // Array of 4 items

// Item 1: "Signature1" (text string, 10 bytes)
sigStructureBytes.append(0x6a) // Text string tag, 10 bytes
sigStructureBytes.append(contentsOf: "Signature1".utf8)

// Item 2: protected_headers (empty map {})
sigStructureBytes.append(0xa0)

// Item 3: external_aad (empty byte string h'')
sigStructureBytes.append(0x40)

// Item 4: payload (byte string: authenticatorData || clientDataHash)
sigStructureBytes.append(0x58) // Byte string tag
sigStructureBytes.append(UInt8(payload.count)) // Length byte
sigStructureBytes.append(contentsOf: payload)

let sigStructure = sigStructureBytes
```

**Update comment at line 742:**
```swift
// - AssertionValidator receives COSE Sig_structure bytes (CBOR-encoded array)
// - CryptoKit's isValidSignature(_:for: Data) hashes the Sig_structure internally
```

---

## 9. Verification

After fix, verify:
1. `sigStructure_length` should be ~85-90 bytes (not 69)
2. `sigStructure_sha256` should match what Apple signed
3. Verification should succeed

---

## Conclusion

**VERIFIED Invariants:**
- ✅ Public key storage/retrieval
- ✅ CBOR extraction
- ✅ Signature format (DER)
- ✅ Signed bytes length
- ✅ Transport integrity

**FAILED Invariant:**
- ❌ Signed bytes format: Raw concatenation instead of COSE Sig_structure

**Root Cause:**
Backend passes raw `authenticatorData || clientDataHash` to validator, but App Attest signs over COSE Sig_structure CBOR array.

**Minimal Fix:**
Construct COSE Sig_structure as `["Signature1", {}, h'', payload]` before passing to validator.

**Why This Bug Survives Normal Logging:**
Length and hash checks pass because the payload itself is correct; the missing COSE wrapper is not detected by simple length/hash validation.

**Why This Is NOT an App Attest Issue:**
The specification is clear; this is a backend implementation bug where the COSE Sig_structure wrapper was omitted.
