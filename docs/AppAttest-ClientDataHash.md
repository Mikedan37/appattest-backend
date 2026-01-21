# App Attest ClientDataHash Authority Contract

## Model Summary

The backend is the sole authority for `clientDataHash` generation, storage, and verification. The complete flow requires three endpoints:

1. **REGISTER**: Backend extracts and stores public key, issues `flowID`
2. **CLIENT_DATA_HASH**: Backend generates challenge, constructs `clientDataJSON`, hashes it to `clientDataHash`, stores it keyed by `(keyID, flowID)`, and supplies it to the frontend
3. **VERIFY**: Backend verifies assertion using stored hash and public key, enforcing all identity bindings before verification

The frontend uses the provided hash exactly once to generate an assertion, then sends the assertion to the backend. The backend verifies the assertion using the stored hash and marks it as consumed. This model ensures replay protection, server authority, and unambiguous verification.

## Complete Message Sequence

```
1. Frontend: POST /app-attest/register
   Request:  { "keyID": "<base64>", "attestationObject": "<base64>" }
   Response: { "status": "registered", "flowID": "<uuid>" }
   
   Backend: Extracts publicKeyX963, validates keyID == SHA256(publicKey),
            stores (keyID, flowID) → publicKeyX963, logs [KEY_REGISTERED]

2. Frontend: POST /app-attest/client-data-hash
   Request:  { "keyID": "<base64>", "flowID": "<uuid>", "verifyRunID": "<optional-uuid>" }
   Response: { "clientDataHash": "<base64>", "expiresAt": "<ISO8601>" }
   
   Backend: Generates challenge, builds clientDataJSON, computes clientDataHash,
            stores (keyID, flowID) → { clientDataHash, verifyRunID, expiresAt, used },
            logs [CLIENT_DATA_HASH]

3. Frontend: generateAssertion(keyID, clientDataHash: <server bytes>)
   Apple signs: authenticatorData || clientDataHash
   (or: authenticatorData || SHA256(clientDataHash) - dual attempts prove which)

4. Frontend: POST /app-attest/verify
   Request:  { "keyID": "<base64>", "flowID": "<uuid>", "assertionObject": "<base64>", "verifyRunID": "<optional-uuid>" }
   Response: { "status": "verified" | "rejected", "reason": "<optional>" }
   
   Backend: 
   - Enforces identity bindings (A, B, C, D) BEFORE verification
   - Loads stored clientDataHash for (keyID, flowID)
   - Loads stored publicKeyX963 for (keyID, flowID)
   - Extracts authenticatorData and signature from assertion CBOR
   - Performs dual DIGEST verification attempts
   - Logs [SIX_VALUES] block
   - Marks clientDataHash as consumed on success
```

## Authority Boundary

| Component | Owns |
|-----------|------|
| **Backend** | Public key extraction and storage (keyed by `(keyID, flowID)`) |
| **Backend** | Challenge generation (32 bytes, cryptographically random) |
| **Backend** | clientDataJSON construction (`{"type":"apple-appattest","challenge":"<base64>","origin":"<bundleID>"}`) |
| **Backend** | clientDataHash computation (`SHA256(clientDataJSON)`) |
| **Backend** | clientDataHash storage (keyed by `(keyID, flowID)`, TTL 5 minutes, one-time-use flag) |
| **Backend** | clientDataHash issuance (supplies hash to frontend on request) |
| **Backend** | Replay protection (rejects expired/consumed hashes) |
| **Backend** | Identity binding enforcement (flowID ↔ keyID, flowID ↔ clientDataHash, keyID ↔ publicKey, flowID ↔ verifyRunID) |
| **Frontend** | Uses provided clientDataHash verbatim (no generation, no modification) |
| **Frontend** | Signs assertion using provided hash (single use, no persistence) |
| **Frontend** | Transports assertion bytes unchanged |
| **Apple** | Signs `authenticatorData || clientDataHash` (or `authenticatorData || SHA256(clientDataHash)`) |
| **Backend** | Verifies signature over exact same bytes using stored hash and stored public key |

## Mandatory Identity Bindings

The backend **MUST** enforce these bindings **BEFORE** attempting cryptographic verification. If any binding fails, reject with explicit reason. Do NOT attempt verification.

### Binding A: flowID ↔ keyID
- **Check:** The stored public key's `flowID` must match the request's `flowID`
- **Failure reason:** `"flowID ↔ keyID binding violation: stored flowID (X) != request flowID (Y)"`
- **When checked:** During VERIFY, after loading stored public key

### Binding B: flowID ↔ clientDataHash
- **Check:** The stored `clientDataHash` must be bound to the request's `flowID`
- **Failure reason:** `"missing_hash"`, `"expired_hash"`, or `"reused_hash"`
- **When checked:** During VERIFY, when consuming clientDataHash

### Binding C: keyID ↔ publicKeyX963
- **Check:** The `keyID` must equal `SHA256(publicKeyX963)` exactly (App Attest invariant)
- **Failure reason:** `"Public key SHA256 does not match keyID - wrong public key stored"`
- **When checked:** During REGISTER (validation) and VERIFY (assertion)

### Binding D: flowID ↔ verifyRunID
- **Check:** If `verifyRunID` is provided, it must match the stored `verifyRunID` for that `flowID`
- **Failure reason:** `"verifyRunID_mismatch"`
- **When checked:** During VERIFY, when consuming clientDataHash (if verifyRunID provided)

**If any binding fails, reject immediately. Do NOT return "DER verification failed" for binding violations.**

## Cryptographic Invariant

Apple signs one of these byte sequences (dual attempts prove which):

**Attempt A (no re-hash):**
```
signedBytes = authenticatorData || clientDataHash
```

**Attempt B (re-hash clientDataHash):**
```
signedBytes = authenticatorData || SHA256(clientDataHash)
```

Where:
- `authenticatorData`: Extracted from assertion CBOR map (key 1 or "authenticatorData", bstr)
- `clientDataHash`: 32-byte SHA256 hash stored and supplied by backend
- `||`: Raw byte concatenation (no encoding, no hashing, **no COSE structures**)

### Verification Process

1. Backend enforces all identity bindings (A, B, C, D)
2. Backend looks up stored `clientDataHash` for `(keyID, flowID)`
3. Backend looks up stored `publicKeyX963` for `(keyID, flowID)`
4. Backend decodes assertion CBOR map (0xa2)
5. Backend extracts `authenticatorData` (bstr) and `signature` (bstr, DER)
6. Backend performs **dual DIGEST verification attempts:**
   - **Attempt A:** `digestA = SHA256(authenticatorData || clientDataHash)`
   - **Attempt B:** `digestB = SHA256(authenticatorData || SHA256(clientDataHash))`
7. Backend verifies: `publicKey.isValidSignature(signatureDER, for: digestA)` OR `publicKey.isValidSignature(signatureDER, for: digestB)`
8. Backend logs `[SIX_VALUES]` block matching frontend format
9. If verification succeeds, mark `clientDataHash` as consumed

**Note:** Both attempts use DIGEST mode (`for: SHA256.Digest`). This eliminates double-hashing confusion and makes the exact digest being verified explicit.

## Storage Keys

All storage uses a canonical storage key format:

```
storageKey = "\(keyIDHex):\(flowID)"
```

Where:
- `keyIDHex`: Lowercase hex representation of raw 32-byte keyID (from base64 decode)
- `flowID`: Backend-issued UUID

This ensures byte-for-byte identical storage keys across REGISTER, CLIENT_DATA_HASH, and VERIFY.

## One-Time Use and Expiry Rules

### TTL (Time To Live)
- Default: 5 minutes from issuance
- Backend rejects expired hashes with reason: `"expired_hash"`

### Consumption
- Hash is marked as `consumed = true` immediately after successful verification
- Backend rejects consumed hashes with reason: `"reused_hash"`
- One hash → one assertion → one verification (enforced)

### Missing Hash
- Backend rejects if no hash exists for `(keyID, flowID)` with reason: `"missing_hash"`
- Frontend must call `/app-attest/client-data-hash` before `/app-attest/verify`

## SIX_VALUES Logging

The backend logs a `SIX_VALUES` block for every verification request. This block **MUST** match the frontend's `SIX_VALUES` block byte-for-byte.

### Backend SIX_VALUES Format

```
---------- SIX_VALUES (verifyRunID=<uuid>) ----------
authenticatorData.sha256=<hex>
clientDataHash.sha256=<hex>
signedBytes.sha256=<hex>        // for the attempt being verified
signature.sha256=<hex>
keyID_sha256=<hex>
publicKeyX963.sha256=<hex>
----------
```

### Frontend SIX_VALUES Format

The frontend should log the same six values after assertion generation, before network send.

### Parity Check

If all six values match byte-for-byte:
- Transport integrity confirmed
- Hash authority confirmed (backend issued, frontend used)
- Signed bytes construction confirmed
- Key continuity confirmed

If values don't match, it's an identity drift issue, not a cryptographic failure.

## Fingerprint Parity Checklist

The following fingerprints must match **byte-for-byte** between frontend and backend logs:

### Frontend Logs (after assertion generation, before network send)
- `keyID_sha256`: SHA256 of raw keyID bytes (not base64 string)
- `clientDataHash_hex`: Hex representation of 32-byte hash
- `clientDataHash_sha256`: SHA256 of clientDataHash bytes
- `assertionObject_sha256`: SHA256 of raw assertion CBOR bytes
- `authenticatorData_sha256`: SHA256 of authenticatorData bytes (extracted from assertion)
- `signedBytes_sha256`: SHA256 of `authenticatorData || clientDataHash` (or with re-hash)
- Lengths: `assertionObject_length`, `authenticatorData_length`, `clientDataHash_length` (should be 32)

### Backend Logs (during verify)
- `[SIX_VALUES]` block with all six values
- `[VERIFY_TRACE][TRANSPORT]` assertionObject.sha256
- `[VERIFY_TRACE][CLIENT_DATA_HASH]` clientDataHash.sha256
- `[VERIFY_TRACE][KEY_IDENTITY]` publicKeyX963.sha256, hex_prefix20, hex_suffix20, base64
- `[VERIFY_TRACE][DECODED]` authenticatorData.sha256, signatureDER.sha256
- `[VERIFY_TRACE][DIGESTS]` attemptA_signedBytes.sha256, attemptB_signedBytes.sha256
- `[VERIFY_TRACE][RESULT]` verification outcome

## Failure Triage

### assertionObject_sha256 Mismatch
- **Cause:** Transport/encoding bug
- **Symptoms:** Frontend and backend see different assertion bytes
- **Fix:** Check base64 encoding/decoding, network transport, JSON serialization
- **Diagnostic:** Compare raw assertion bytes (hex dump) on both sides

### clientDataHash_sha256 Mismatch
- **Cause:** Storage/issuance mismatch or frontend used wrong hash
- **Symptoms:** Frontend used a different hash than backend issued
- **Fix:** 
  - Ensure frontend uses hash from `/app-attest/client-data-hash` response
  - Ensure backend stores/retrieves hash correctly (check `(keyID, flowID)` binding)
  - Ensure frontend doesn't regenerate or modify hash
- **Diagnostic:** Log hash at issuance and at verification, compare

### signedBytes_sha256 Mismatch
- **Cause:** authenticatorData extraction or concatenation bug
- **Symptoms:** Backend constructed signedBytes incorrectly
- **Fix:** 
  - Verify `signedBytes = authenticatorData || clientDataHash` (raw concatenation)
  - Check authenticatorData extraction from CBOR map (integer key 1 or text key "authenticatorData")
  - Ensure no encoding/hashing of signedBytes before concatenation
- **Diagnostic:** Log authenticatorData length and first/last bytes, verify concatenation

### Binding Violations
- **Cause:** flowID mismatch, keyID mismatch, or verifyRunID mismatch
- **Symptoms:** Rejection with explicit binding violation reason
- **Fix:**
  - Ensure frontend reuses the same `flowID` from REGISTER response
  - Ensure frontend sends the same `verifyRunID` (if provided) to CLIENT_DATA_HASH and VERIFY
  - Check backend storage key construction (must use canonical format)
- **Diagnostic:** Log all binding values at each endpoint, compare

### All Fingerprints Match But Verify Fails
- **Cause:** Public key extraction/storage bug OR signature API misuse OR wrong signing theory
- **Symptoms:** Bytes are correct but signature doesn't verify
- **Fix:** 
  - Check public key format (X9.63, 65 bytes, 0x04 prefix)
  - Check signature DER encoding (starts with 0x30, valid ASN.1)
  - Verify API usage: DIGEST mode (`for: SHA256.Digest`), not MESSAGE mode
  - Check which dual attempt succeeded (A or B) to determine correct signing theory
- **Diagnostic:** Dump public key, signature, and signedBytes to files, verify with OpenSSL

## API Contract

### POST /app-attest/register

**Request:**
```json
{
  "keyID": "<base64>",
  "attestationObject": "<base64>"
}
```

**Response:**
```json
{
  "status": "registered" | "rejected",
  "reason": "<optional>",
  "flowID": "<uuid>",
  "publicKeySha256": "<hex>"  // Debug-only, nil in release
}
```

**Behavior:**
1. Decode keyID base64 to bytes (must be 32 bytes)
2. Decode attestationObject base64 to bytes
3. Decode attestation CBOR to extract public key
4. Validate `keyID == SHA256(publicKeyX963)` (App Attest invariant)
5. Generate `flowID` (UUID)
6. Store: `(keyID, flowID) → publicKeyX963` with fingerprint
7. Log: `[KEY_REGISTERED]` with public key fingerprint
8. Return `flowID` to frontend

**Idempotency:**
- **Idempotent:** Multiple REGISTER requests with the same `keyID` and `attestationObject` are allowed
- **Behavior:** If a public key already exists for `(keyID, flowID)`, the existing entry is preserved
- **New flowID:** Each REGISTER request generates a new `flowID`, even for the same `keyID`
- **Use case:** Allows re-registration after backend restart or for testing

**Errors:**
- `200 OK` with `"rejected"`: Invalid attestation, keyID mismatch, or storage failure

### POST /app-attest/client-data-hash

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "verifyRunID": "<optional-uuid>"
}
```

**Response:**
```json
{
  "clientDataHash": "<base64>",
  "expiresAt": "<ISO8601>"
}
```

**Behavior:**
1. Decode keyID base64 to bytes
2. Validate `flowID` is not empty
3. Generate 32-byte cryptographically random challenge
4. Build canonical clientDataJSON:
   ```json
   {
     "type": "apple-appattest",
     "challenge": "<base64(challenge)>",
     "origin": "<bundleID>"
   }
   ```
5. Compute `clientDataHash = SHA256(UTF8(clientDataJSON))`
6. Store hash keyed by `(keyID, flowID)` with:
   - `clientDataHash`: 32 bytes
   - `verifyRunID`: optional UUID for tracing
   - `generatedAt`: creation time
   - `expiresAt`: timestamp + 5 minutes
   - `used`: false (one-time-use flag)
7. Log: `[CLIENT_DATA_HASH]` with hash and verifyRunID
8. Return hash and expiry

**Idempotency:**
- **Write-once immutable:** Each `(keyID, flowID)` pair can have exactly one `clientDataHash`
- **Strict enforcement:** If a `clientDataHash` already exists for `(keyID, flowID)`, the request is rejected with `409 Conflict`
- **Rationale:** Ensures one hash per flow, preventing hash swapping attacks and maintaining replay protection
- **Error:** `409 Conflict` with reason indicating write-once immutable violation

**Errors:**
- `400 Bad Request`: Invalid keyID format, missing flowID
- `409 Conflict`: clientDataHash already exists for `(keyID, flowID)` (write-once immutable - each `(keyID, flowID)` pair can have exactly one hash)
- `500 Internal Server Error`: Hash generation failed

### POST /app-attest/verify

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "assertionObject": "<base64>",
  "verifyRunID": "<optional-uuid>"
}
```

**Response:**
```json
{
  "status": "verified" | "rejected",
  "reason": "<optional error message>"
}
```

**Behavior:**
1. Decode keyID base64 to bytes
2. Validate `flowID` is not empty
3. **Enforce identity bindings (A, B, C, D) BEFORE verification:**
   - **Binding A:** Load stored public key, check `storedFlowID == requestFlowID`
   - **Binding B:** Consume stored clientDataHash, check `flowID` binding
   - **Binding C:** Validate `keyID == SHA256(publicKeyX963)`
   - **Binding D:** If verifyRunID provided, check `storedVerifyRunID == requestVerifyRunID`
4. If any binding fails, reject immediately with explicit reason
5. Decode assertionObject base64 to bytes
6. Decode assertion CBOR map (0xa2)
7. Extract `authenticatorData` (bstr, key 1 or "authenticatorData")
8. Extract `signature` (bstr, key 2 or "signature", DER format)
9. Perform dual DIGEST verification attempts:
   - **Attempt A:** `digestA = SHA256(authenticatorData || clientDataHash)`
   - **Attempt B:** `digestB = SHA256(authenticatorData || SHA256(clientDataHash))`
10. Verify: `publicKey.isValidSignature(signatureDER, for: digestA)` OR `publicKey.isValidSignature(signatureDER, for: digestB)`
11. Log: `[SIX_VALUES]` block matching frontend format
12. If verification succeeds:
    - Mark clientDataHash as consumed
    - Return `{"status": "verified"}`
13. If verification fails:
    - Do NOT consume hash (allow retry with new hash)
    - Return `{"status": "rejected", "reason": "..."}`

**Errors:**
- `200 OK` with `"rejected"`: 
  - Binding violations: `"flowID ↔ keyID binding violation"`, `"verifyRunID_mismatch"`
  - Lifecycle violations: `"missing_hash"`, `"expired_hash"`, `"reused_hash"`
  - Format errors: `"Invalid keyID format"`, `"Invalid assertionObject format"`
  - Verification failures: `"DER signature verification failed"`

## Error Handling

- **No fatal errors:** All errors are logged and returned to the client
- **No crashes:** Invalid inputs return rejection responses, not crashes
- **Explicit reasons:** All rejections include a `reason` field explaining why
- **Binding violations:** Reject immediately, do NOT attempt verification

## Production Considerations

### Log Redaction

In production environments, consider redacting sensitive values from logs:

- **Public keys:** Consider redacting `publicKeyX963.hex_full` and `publicKeyX963.base64` (keep `publicKeyX963.sha256` for lineage tracking)
- **Signatures:** Consider redacting `signature.hex` (keep `signature.sha256` for integrity)
- **KeyIDs:** Consider redacting full `keyID` values (keep `keyID_sha256` for correlation)
- **ClientDataHash:** Consider redacting `clientDataHash.hex` (keep `clientDataHash.sha256` for verification)

**Recommended approach:**
- Keep all SHA256 hashes (needed for SIX_VALUES parity and debugging)
- Keep hex prefixes/suffixes (needed for identity verification)
- Redact full hex/base64 representations of keys and signatures
- Log redaction should be configurable via environment variable

**Example redaction policy:**
```swift
#if PRODUCTION
let publicKeyHex = publicKeyData.prefix(8).map { String(format: "%02x", $0) }.joined() + "...[REDACTED]"
#else
let publicKeyHex = publicKeyData.map { String(format: "%02x", $0) }.joined()
#endif
```

## Anti-Patterns (Explicitly Forbidden)

### Frontend Generating Hash
```swift
// WRONG - Frontend must never do this
let challenge = generateChallenge()
let clientDataJSON = buildClientDataJSON(challenge: challenge)
let clientDataHash = SHA256.hash(data: clientDataJSON)
generateAssertion(keyID, clientDataHash: clientDataHash)
```
**Why wrong:** Backend loses authority and cannot verify what was actually signed.

### Backend Recomputing Hash at Verify Time
```swift
// WRONG - Backend must use stored hash
let challenge = retrieveChallenge(keyID)  // WRONG - challenge not stored
let clientDataJSON = buildClientDataJSON(challenge: challenge)
let clientDataHash = SHA256.hash(data: clientDataJSON)  // WRONG - should use stored hash
```
**Why wrong:** Backend must use the exact hash it issued, not recompute it. Challenge is not stored, only the hash.

### Accepting Client-Provided Hash
```swift
// WRONG - Backend must never accept hash from client
struct VerifyRequest {
    let keyID: String
    let assertionObject: String
    let clientDataHash: String  // WRONG - remove this field
}
```
**Why wrong:** Client could supply a different hash than what was issued, breaking replay protection.

### Using Different flowID Across Endpoints
```swift
// WRONG - flowID must be reused
let flowID1 = register()  // Returns flowID: "ABC-123"
let hash = clientDataHash(flowID: "XYZ-789")  // WRONG - different flowID
verify(flowID: "XYZ-789")  // WRONG - binding violation
```
**Why wrong:** flowID binds keyID, clientDataHash, and publicKey together. Using different flowIDs breaks bindings.

### Attempting Verification Before Binding Checks
```swift
// WRONG - Check bindings first
let isValid = verifySignature(...)  // WRONG - check bindings first
if storedFlowID != requestFlowID { ... }  // Too late
```
**Why wrong:** Binding violations should be caught immediately, not after expensive cryptographic operations.

## Summary

This contract locks down:
1. **Complete flow:** REGISTER → CLIENT_DATA_HASH → VERIFY
2. **Storage keys:** Canonical format `"\(keyIDHex):\(flowID)"`
3. **Identity bindings:** Four mandatory bindings (A, B, C, D) enforced before verification
4. **Cryptographic invariant:** Dual DIGEST attempts to prove correct signing theory
5. **SIX_VALUES logging:** Byte-for-byte parity between frontend and backend
6. **Error handling:** Safe, explicit, no crashes
7. **Client/server authority boundary:** Backend owns hash and public key, frontend uses them
8. **Replay protection:** One-time-use hashes with TTL

The backend is the authoritative source for `clientDataHash` and `publicKeyX963`. The frontend is a pure signer and transport.
