# Debugging ClientDataHash Response Issues

## Frontend Error: "clientDataHash response must contain clientDataHash field"

This error indicates the frontend is not finding the `clientDataHash` field in the JSON response.

## Backend Response Format

The backend **guarantees** this exact JSON structure:

```json
{
  "clientDataHash": "<base64_string>",
  "expiresAt": "<ISO8601_timestamp>"
}
```

## Verification Steps

### 1. Test Backend Response Directly

```bash
curl -v -X POST http://10.0.0.108:8080/app-attest/client-data-hash \
  -H "Content-Type: application/json" \
  -d '{"keyID":"nkXn/k+XJgK72BFM9gOeZlxGbwHoOcl+nSDglqUrUZQ="}'
```

**Expected output:**
```json
{
  "clientDataHash": "dGVzdGluZzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9w==",
  "expiresAt": "2026-01-17T05:32:00Z"
}
```

### 2. Check Backend Logs

Look for this log entry:
```
CLIENT_DATA_HASH response ready
- response_clientDataHash_present: true
- response_clientDataHash_length: 44
- response_expiresAt_present: true
- response_expiresAt_value: <ISO8601>
```

If these are missing or false, the backend has an issue.

### 3. Verify JSON Encoding

The backend uses Vapor's `Content` protocol which automatically encodes to JSON. The struct is:

```swift
struct ClientDataHashResponse: Content {
    let clientDataHash: String
    let expiresAt: String
    
    enum CodingKeys: String, CodingKey {
        case clientDataHash
        case expiresAt
    }
}
```

### 4. Common Issues

#### Issue: Vapor JSON Encoding
- **Symptom:** Response is empty or malformed
- **Fix:** Ensure Vapor's JSON encoder is configured correctly
- **Check:** Backend logs should show response structure

#### Issue: Field Name Mismatch
- **Symptom:** Frontend expects different field name
- **Fix:** Backend uses exact field names: `clientDataHash` and `expiresAt`
- **Check:** Use curl to verify actual response

#### Issue: Network/Transport
- **Symptom:** Response is truncated or modified
- **Fix:** Check network logs, verify full response received
- **Check:** Use curl with `-v` flag to see raw HTTP response

### 5. Frontend Parsing

The frontend should decode as:

```swift
struct ClientDataHashResponse: Codable {
    let clientDataHash: String
    let expiresAt: String
}
```

**Critical:** Field names must match exactly (case-sensitive).

## Debugging Checklist

- [ ] Backend returns HTTP 200 (not 500/400)
- [ ] Response body contains both `clientDataHash` and `expiresAt` fields
- [ ] Field names are exactly `clientDataHash` and `expiresAt` (case-sensitive)
- [ ] `clientDataHash` is a non-empty base64 string
- [ ] `expiresAt` is a valid ISO8601 timestamp
- [ ] Frontend JSON decoder uses matching struct field names
- [ ] Network response is not truncated or modified

## Quick Test Script

```bash
#!/bin/bash
# test_client_data_hash.sh

KEYID="nkXn/k+XJgK72BFM9gOeZlxGbwHoOcl+nSDglqUrUZQ="
URL="http://10.0.0.108:8080/app-attest/client-data-hash"

echo "Testing backend response..."
RESPONSE=$(curl -s -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d "{\"keyID\":\"$KEYID\"}")

echo "Response: $RESPONSE"
echo ""

# Check for required fields
if echo "$RESPONSE" | grep -q '"clientDataHash"'; then
    echo "✅ clientDataHash field present"
else
    echo "❌ clientDataHash field MISSING"
fi

if echo "$RESPONSE" | grep -q '"expiresAt"'; then
    echo "✅ expiresAt field present"
else
    echo "❌ expiresAt field MISSING"
fi

# Validate JSON
if echo "$RESPONSE" | python3 -m json.tool > /dev/null 2>&1; then
    echo "✅ Valid JSON"
else
    echo "❌ Invalid JSON"
fi
```

Run this script to verify the backend response format.
