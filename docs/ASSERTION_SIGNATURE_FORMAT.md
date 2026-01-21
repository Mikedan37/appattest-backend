# App Attest Assertion Signature Format

## Symptom

Verification fails with `{"status":"rejected","reason":"Signature did not verify under the supplied public key"}` even though:
- `keyID` matches between registration and verification
- `clientDataHash` is exactly 32 bytes and byte-for-byte identical
- `assertionObject` SHA256 matches between client and backend
- Registration succeeded

## Root Cause

The most common cause is a signature format mismatch between what Apple provides and what the crypto library expects.

### Signature Format Options

App Attest assertions can provide ECDSA signatures in two formats:

1. **Raw format (64 bytes)**: `r[32] || s[32]`
   - 32-byte r coordinate (big-endian)
   - 32-byte s coordinate (big-endian)
   - Total: 64 bytes

2. **ASN.1 DER format (70-72 bytes)**: `SEQUENCE { INTEGER r, INTEGER s }`
   - Starts with `0x30` (SEQUENCE tag)
   - Variable length depending on leading zeros in r and s
   - Total: typically 70-72 bytes

### CryptoKit Expectation

CryptoKit's `P256.Signing.PublicKey.isValidSignature(_:for:)` expects ASN.1 DER format.

## How to Detect

Check backend logs for `signature_length`:

- **64 bytes** → Raw format, must convert to DER before verification
- **70-72 bytes, starts with 0x30** → Already DER, use as-is
- **Other lengths** → Invalid format

Also verify `signedBytes_length` equals:
```
authenticatorData_length + 32
```

## Fix

### If signature is 64 bytes (raw):

Convert raw `r||s` to ASN.1 DER:

1. Split into r and s (32 bytes each)
2. Remove leading zeros (but keep at least one byte)
3. If high bit is set, prepend `0x00` to indicate positive
4. Encode each as ASN.1 INTEGER
5. Wrap in SEQUENCE: `0x30 || length || r_INTEGER || s_INTEGER`

### If signature is already DER:

Use as-is, but verify it starts with `0x30`.

## Signed Bytes Construction

The signed bytes MUST be:

```
signedBytes = authenticatorData || clientDataHash
```

**Critical rules:**
- Raw concatenation only (no hashing, no encoding)
- Use exact bytes from CBOR extraction
- Use exact `clientDataHash` from request (32 bytes)
- Do NOT recompute `clientDataHash`
- Do NOT wrap in CBOR or JSON
- Do NOT include challenge strings

## Public Key Format

The public key must be in the format expected by the verifier:

- **CryptoKit**: Expects X9.63 format (65 bytes: `0x04 || X[32] || Y[32]`)
- **Other libraries**: May expect SPKI/DER SubjectPublicKeyInfo

Ensure the stored key matches the verifier's expectation.

## Diagnostic Logging

The backend logs the following for each verify request:

- `signature_length` - Length in bytes (64 = raw, 70-72 = DER)
- `signature_firstByte` - First byte (0x30 = DER)
- `signedBytes_length` - Should equal `authenticatorData_length + 32`
- `signedBytes_sha256` - SHA256 of constructed signed bytes
- `authenticatorData_length` - Length of authenticatorData
- `clientDataHash_length` - Should be 32

Compare these between client and backend to identify mismatches.

## Common Mistakes

**Treating 64-byte signature as DER**
- Result: Verification always fails
- Fix: Convert raw to DER

**Hashing signedBytes before verification**
- Result: Double-hashing (SHA256(SHA256(payload)))
- Fix: Pass raw bytes, let CryptoKit hash

**Recomputing clientDataHash**
- Result: Different bytes than what Apple signed
- Fix: Use exact bytes from request

**Wrong signedBytes construction**
- Result: Verifying wrong message
- Fix: `authenticatorData || clientDataHash` only

## Example: Raw to DER Conversion

```swift
// Input: 64-byte raw signature
let rawSig = Data([...]) // 64 bytes: r[32] || s[32]

// Split
let r = rawSig.prefix(32)
let s = rawSig.suffix(32)

// Encode each as ASN.1 INTEGER (with leading zero handling)
let rDER = encodeASN1Integer(r)
let sDER = encodeASN1Integer(s)

// Wrap in SEQUENCE
var der = Data([0x30]) // SEQUENCE tag
der.append(UInt8(rDER.count + sDER.count)) // length
der.append(contentsOf: rDER)
der.append(contentsOf: sDER)

// Result: ~70-72 byte DER signature
```

## Verification

After fixing, verify:
1. Valid assertion returns `{"status":"verified"}`
2. Tampered `clientDataHash` (1 byte changed) returns `{"status":"rejected"}`
3. Backend logs show correct `signature_length` and `signedBytes_length`
