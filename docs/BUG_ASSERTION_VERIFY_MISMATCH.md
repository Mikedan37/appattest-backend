# Bug: App Attest Assertion Verification Mismatch

## What Was Wrong

App Attest assertion verification was failing with `{"status":"rejected","reason":"Signature did not verify under the supplied public key"}` even when:
- Registration succeeded
- KeyID continuity was maintained
- `clientDataHash` was byte-for-byte identical
- `assertionObject` was transmitted intact

## How We Detected It

Added comprehensive diagnostic logging to compare byte-for-byte invariants between client and backend:

### Backend Logs (per verify request):

1. **Key Material**:
   - `keyID_base64` - The keyID as received
   - `keyID_sha256` - SHA256 of keyID
   - `storedPublicKey_length` - Length of retrieved public key (should be 65)
   - `storedPublicKey_sha256` - SHA256 of stored public key bytes
   - `storedPublicKey_firstByte` - Should be `0x04` for X9.63 format
   - `storedPublicKey_format` - Format indicator

2. **CBOR Parsing**:
   - `mapKeys` - All keys present in CBOR map (as integers where possible)
   - `authenticatorDataKey` - Which key was used (1, text:authenticatorData, etc.)
   - `authenticatorData_length` - Length in bytes
   - `authenticatorData_sha256` - SHA256 of extracted bytes
   - `signatureKey` - Which key was used (2, text:signature, etc.)
   - `signature_length` - Length in bytes (64 = raw, 70-72 = DER)
   - `signature_firstByte` - First byte (0x30 = DER)
   - `signature_sha256` - SHA256 of raw signature bytes

3. **Signature Format Conversion**:
   - `signature_converted` - "raw→DER" or "already-DER"
   - `der_signature_length` - Length after conversion
   - `der_signature_firstByte` - Should be 0x30
   - `der_signature_sha256` - SHA256 of DER signature

4. **Signed Bytes Construction**:
   - `signedBytes_length` - Must equal `authenticatorData_length + 32`
   - `signedBytes_sha256` - SHA256 of `authenticatorData || clientDataHash`

5. **Verification Result**:
   - `VERIFY result: verified` or `VERIFY result: rejected`
   - Full diagnostic metadata including all hashes

## Invariants to Check

When comparing client and backend logs, these must match exactly:

### Must Match:
- `assertionObject_sha256` - Proves transport integrity
- `clientDataHash_hex` - Proves clientDataHash byte fidelity
- `authenticatorData_length` - Proves extraction succeeded
- `authenticatorData_sha256` - Proves correct bytes extracted
- `signature_length` - Proves signature extraction succeeded
- `signature_sha256` - Proves correct signature bytes extracted
- `signedBytes_sha256` - Proves signedBytes construction is correct

### Must Validate:
- `signedBytes_length == authenticatorData_length + 32`
- `storedPublicKey_length == 65`
- `storedPublicKey_firstByte == 0x04`
- `signature_length` is 64 (raw) or 70-72 (DER)
- If `signature_length == 64`, conversion to DER must occur
- If `signature_firstByte == 0x30`, use as-is (already DER)

## Common Failure Modes

### 1. Wrong Public Key Retrieved
**Symptoms**:
- `storedPublicKey_sha256` differs between register and verify
- `keyID_sha256` matches but wrong key retrieved

**Causes**:
- KeyID normalization mismatch (base64 vs base64url, padding)
- Storage key format mismatch (hex vs base64)
- Key overwritten during later flows

### 2. Signature Format Mismatch
**Symptoms**:
- `signature_length: 64` but verification fails
- `signature_firstByte` is not 0x30 but signature is treated as DER

**Causes**:
- Raw signature not converted to DER
- DER signature double-wrapped
- DER conversion bug (INTEGER encoding, sign bit handling)

### 3. Wrong Signed Bytes Construction
**Symptoms**:
- `signedBytes_length != authenticatorData_length + 32`
- `signedBytes_sha256` doesn't match expected

**Causes**:
- Hashing signedBytes before verification
- CBOR/JSON encoding applied
- Wrong concatenation order
- Extra bytes included

### 4. CBOR Extraction Mismatch
**Symptoms**:
- `authenticatorData_length: 0` or extraction failure
- `mapKeys` shows integer keys but text keys used

**Causes**:
- Using text keys when integer keys present
- Wrong CBOR key extraction
- Bytes extracted from wrong field

## Exact Log Fields to Compare

### Client Side (iOS):
```
assertionObject_sha256: <hex>
clientDataHash_hex: <hex>
authenticatorData_length: <number>
authenticatorData_sha256: <hex>
signature_length: <number>
signature_firstByte: <hex>
signature_sha256: <hex>
signedBytes_sha256: <hex>
```

### Backend Side:
```
assertionObject_sha256: <hex>  ← MUST MATCH
clientDataHash_hex: <hex>      ← MUST MATCH
authenticatorData_length: <number>  ← MUST MATCH
authenticatorData_sha256: <hex>     ← MUST MATCH
signature_length: <number>          ← MUST MATCH
signature_sha256: <hex>             ← MUST MATCH
signedBytes_sha256: <hex>           ← MUST MATCH
storedPublicKey_length: 65          ← MUST BE 65
storedPublicKey_firstByte: 0x04     ← MUST BE 0x04
```

## Resolution

Once all hashes match and verification still fails, the issue is:
- Public key format mismatch (SPKI vs X9.63)
- DER conversion bug
- CryptoKit API misuse

The diagnostic logs will show exactly which one.
