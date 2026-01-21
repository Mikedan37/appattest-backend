# ClientDataHash Response Format

## Backend Response Contract

The backend **guarantees** the following JSON response format for `POST /app-attest/client-data-hash`:

### Response Structure

```json
{
  "clientDataHash": "<base64_string>",
  "expiresAt": "<ISO8601_timestamp>"
}
```

### Field Specifications

#### `clientDataHash` (required)
- **Type:** String
- **Format:** Standard base64 encoding (RFC 4648)
- **Length:** 44 characters (32 bytes encoded)
- **Encoding:** Uses `+` and `/`, includes `=` padding
- **Example:** `"dGVzdGluZzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w=="`

#### `expiresAt` (required)
- **Type:** String
- **Format:** ISO8601 timestamp (UTC)
- **Example:** `"2026-01-17T12:00:00Z"`

### Response Validation

The backend logs response structure validation:
- `clientDataHash_present`: true
- `clientDataHash_length`: 44 (for 32-byte hash)
- `expiresAt_present`: true
- `expiresAt_value`: ISO8601 timestamp

### Frontend Parsing

The frontend should parse the response as:

```swift
struct ClientDataHashResponse: Codable {
    let clientDataHash: String
    let expiresAt: String
}
```

**Critical:** Both fields are **required**. If either is missing, the response is invalid.

### Error Cases

If the backend cannot generate a hash:
- Returns HTTP 500 with error message
- Response body: `{"error": "ClientDataHash generation failed"}`

If the keyID is invalid:
- Returns HTTP 400 with error message
- Response body: `{"error": "Invalid keyID format: <details>"}`

### Example Valid Response

```json
{
  "clientDataHash": "dGVzdGluZzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w==",
  "expiresAt": "2026-01-17T12:05:00Z"
}
```

### Testing

To verify the response format:

```bash
curl -X POST http://localhost:8080/app-attest/client-data-hash \
  -H "Content-Type: application/json" \
  -d '{"keyID":"<base64_keyID>"}' | jq .
```

Expected output:
```json
{
  "clientDataHash": "<base64>",
  "expiresAt": "<ISO8601>"
}
```

Both fields must be present and non-empty.
