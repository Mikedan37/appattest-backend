# Base64 Encoding Guarantee

## Backend Encoding Contract

The backend **guarantees** canonical base64 encoding for all base64 fields in responses:

### Standard Base64 (RFC 4648)
- Uses characters: `A-Z`, `a-z`, `0-9`, `+`, `/`
- **Does NOT use** base64url characters: `-`, `_`
- **Always includes** padding: `=` characters at the end
- No whitespace or newlines

### Implementation

All base64 encoding in the backend uses Swift's standard `Data.base64EncodedString()` method:

```swift
let clientDataHashBase64 = clientDataHash.base64EncodedString()
```

This method:
- Produces standard base64 (not base64url)
- Includes padding automatically
- No whitespace

### Response Format

**POST /app-attest/client-data-hash**

```json
{
  "clientDataHash": "<standard_base64_with_padding>",
  "expiresAt": "<ISO8601>"
}
```

Example:
```json
{
  "clientDataHash": "dGVzdGluZzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w==",
  "expiresAt": "2026-01-17T12:00:00Z"
}
```

### Validation

The backend logs encoding validation:
- `clientDataHash_base64_hasPadding`: true/false
- `clientDataHash_base64_isStandard`: true/false (checks for base64url chars)

If base64url characters are detected, an error is logged (this should never happen with standard encoding).

### Frontend Decoding

The frontend should use standard base64 decoding:

```swift
guard let hashData = Data(base64Encoded: response.clientDataHash), hashData.count == 32 else {
    // Handle error
}
```

If the frontend needs to be resilient to encoding variations, use a relaxed decoder (see frontend implementation).

### Why This Matters

- **iOS `Data(base64Encoded:)`** expects standard base64 with padding
- **Base64url** (used in JWTs) will fail iOS decoding
- **Missing padding** will fail iOS decoding
- **Whitespace** can cause parsing issues

The backend guarantees standard base64, so the frontend can use strict decoding.
