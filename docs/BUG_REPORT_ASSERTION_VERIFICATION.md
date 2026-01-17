# Bug Report: App Attest Assertion Verification Failure

## Summary

App Attest assertion verification fails on the backend even though:
- Registration succeeds
- KeyID continuity is enforced
- `clientDataHash` is byte-for-byte correct
- `assertionObject` is transmitted intact

Backend rejects with:

```json
{"status":"rejected","reason":"Signature did not verify under the supplied public key"}
```

## Impact

Valid iOS clients are rejected as untrusted. This blocks App Attest rollout entirely.

## Root Cause (Most Likely)

One or more of the following backend issues:

### 1. CBOR Key Mismatch

**Issue**: Apple App Attest assertion objects use **integer CBOR keys**, not text string keys.

**Spec**: 
- Key `1` → `authenticatorData`
- Key `2` → `signature`

**Backend mistake**: Using `.textString("authenticatorData")` and `.textString("signature")` extracts `nil`, causing wrong bytes to be used for verification.

**Detection**: Backend logs show `authenticatorData_length: 0` or extraction failure.

### 2. ECDSA Signature Format Mismatch

**Issue**: iOS returns raw ECDSA signatures (64 bytes: `r[32] || s[32]`), but CryptoKit expects ASN.1 DER format (~70-72 bytes).

**Backend mistake**: Passing raw 64-byte signature to DER-expecting verifier, or double-encoding DER.

**Detection**: Backend logs show `signature_length: 64` but verification still fails.

### 3. Incorrect Signed Bytes Construction

**Issue**: Signed bytes must be raw concatenation:

```
signedBytes = authenticatorData || clientDataHash
```

**Backend mistake**: Hashing, CBOR-encoding, or otherwise mutating the bytes before verification.

**Detection**: Backend logs show `signedBytes_length != authenticatorData_length + 32`.

### 4. Public Key Format Mismatch

**Issue**: Public key extracted correctly but passed to verifier in wrong format (SPKI vs raw EC point).

**Detection**: Verification fails even with correct signedBytes and signature format.

## How to Detect This Bug

Add diagnostic logging and check:

1. **CBOR Key Extraction**:
   - Log which keys are present in the CBOR map
   - Verify `authenticatorData` is extracted (length > 0)
   - Verify `signature` is extracted (length > 0)

2. **Signature Format**:
   - `signature_length: 64` → Raw format, must convert to DER
   - `signature_length: 70-72` → Already DER, use as-is

3. **Signed Bytes**:
   - `signedBytes_length == authenticatorData_length + 32`
   - `signedBytes_sha256` matches expected hash

4. **Data Integrity**:
   - `assertionObject_sha256` matches client
   - `clientDataHash_hex` matches client

If all match and verification still fails → signature/key format mismatch.

## Why This is Dangerous

This failure mode looks like:
- Bad key
- Replay attack
- Client tampering

...but it's actually a backend parsing bug. Without deep logging, engineers will waste days debugging the wrong side.

## Fix

### CBOR Key Extraction

Use integer keys per spec:

```swift
// Try integer keys first (spec-compliant)
let authData = map[.unsigned(1)]?.bytes ?? map[.textString("authenticatorData")]?.bytes
let sig = map[.unsigned(2)]?.bytes ?? map[.textString("signature")]?.bytes
```

### Signature Format Conversion

If `signature_length == 64`, convert raw to DER:

```swift
if signature.count == 64 {
    // Split r and s (32 bytes each)
    let r = signature.prefix(32)
    let s = signature.suffix(32)
    
    // Encode as ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
    let rDER = encodeASN1Integer(r)
    let sDER = encodeASN1Integer(s)
    let der = buildDERSequence(rDER, sDER)
    
    signatureDER = der
}
```

### Signed Bytes Construction

Must be raw concatenation:

```swift
let signedBytes = authenticatorData + clientDataHash
// No hashing, no encoding, no mutation
```

## Recommendation

- Treat App Attest verification as binary-exact cryptography, not "structured data parsing"
- Log hashes, lengths, and first bytes
- Never regenerate or recompute `clientDataHash`
- Never assume DER unless you explicitly create it
- Use integer CBOR keys per Apple's spec

## Verification

After fixing, verify:
1. Valid assertion returns `{"status":"verified"}`
2. Tampered `clientDataHash` (1 byte changed) returns `{"status":"rejected"}`
3. Backend logs show correct key extraction and signature format
