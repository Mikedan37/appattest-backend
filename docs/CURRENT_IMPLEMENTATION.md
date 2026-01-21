# Current Backend Implementation (2026-01-17)

## Overview

This document describes the current state of the App Attest backend implementation, including all recent updates for safe error handling, identity bindings, and SIX_VALUES logging.

## Complete Flow

### 1. REGISTER Endpoint

**Route:** `POST /app-attest/register`

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

**Backend Behavior:**
1. Decodes `keyID` from base64 (must be 32 bytes)
2. Decodes `attestationObject` from base64
3. Decodes attestation CBOR to extract public key
4. Validates `keyID == SHA256(publicKeyX963)` (App Attest invariant)
5. Generates `flowID` (UUID)
6. Stores: `(keyID, flowID) → publicKeyX963` with fingerprint
7. Logs: `[KEY_REGISTERED]` with:
   - `publicKeyX963.sha256`
   - `publicKeyX963.hex_prefix20`
   - `publicKeyX963.hex_suffix20`
   - `publicKeyX963.hex_full`
   - `publicKeyX963.base64`
8. Returns `flowID` to frontend

**Idempotency:**
- **Idempotent:** Multiple REGISTER requests with the same `keyID` and `attestationObject` are allowed
- **Behavior:** If a public key already exists for `(keyID, flowID)`, the existing entry is preserved
- **New flowID:** Each REGISTER request generates a new `flowID`, even for the same `keyID`
- **Use case:** Allows re-registration after backend restart or for testing

**Storage Key Format:**
```
storageKey = "\(keyIDHex):\(flowID)"
```
Where `keyIDHex` is lowercase hex of raw 32-byte keyID.

### 2. CLIENT_DATA_HASH Endpoint

**Route:** `POST /app-attest/client-data-hash`

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

**Backend Behavior:**
1. Decodes `keyID` from base64
2. Validates `flowID` is not empty (rejects with `400 Bad Request` if empty)
3. Generates 32-byte cryptographically random challenge
4. Builds canonical `clientDataJSON`:
   ```json
   {
     "type": "apple-appattest",
     "challenge": "<base64(challenge)>",
     "origin": "<bundleID>"
   }
   ```
5. Computes `clientDataHash = SHA256(UTF8(clientDataJSON))`
6. Stores hash keyed by `(keyID, flowID)` with:
   - `clientDataHash`: 32 bytes
   - `verifyRunID`: optional UUID for tracing
   - `generatedAt`: creation timestamp
   - `expiresAt`: timestamp + 5 minutes
   - `used`: false (one-time-use flag)
7. Logs: `[CLIENT_DATA_HASH]` with hash and verifyRunID
8. Returns hash and expiry

**Storage Key Format:** Same as REGISTER (`"\(keyIDHex):\(flowID)"`)

**Idempotency:**
- **Write-once immutable:** Each `(keyID, flowID)` pair can have exactly one `clientDataHash`
- **Strict enforcement:** If a `clientDataHash` already exists for `(keyID, flowID)`, the request is rejected with `409 Conflict`
- **Rationale:** Ensures one hash per flow, preventing hash swapping attacks and maintaining replay protection
- **Error:** `409 Conflict` with reason indicating write-once immutable violation

**Error Handling:**
- `400 Bad Request`: Invalid keyID format, missing flowID
- `409 Conflict`: clientDataHash already exists for `(keyID, flowID)` (write-once immutable - each `(keyID, flowID)` pair can have exactly one hash)
- `500 Internal Server Error`: Hash generation failed

### 3. VERIFY Endpoint

**Route:** `POST /app-attest/verify`

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

**Backend Behavior:**

1. **Decode and Validate Inputs:**
   - Decodes `keyID` from base64
   - Validates `flowID` is not empty (rejects if empty)
   - Decodes `assertionObject` from base64

2. **Enforce Identity Bindings (BEFORE Verification):**
   
   **Binding A: flowID ↔ keyID**
   - Loads stored public key for `(keyID, flowID)`
   - Checks `storedFlowID == requestFlowID`
   - If mismatch: Reject with `"flowID ↔ keyID binding violation"`
   
   **Binding B: flowID ↔ clientDataHash**
   - Consumes stored clientDataHash for `(keyID, flowID)`
   - Validates hash exists, not expired, not consumed
   - If violation: Reject with `"missing_hash"`, `"expired_hash"`, or `"reused_hash"`
   
   **Binding C: keyID ↔ publicKeyX963**
   - Validates `keyID == SHA256(publicKeyX963)` exactly
   - If mismatch: Reject with `"Public key SHA256 does not match keyID"`
   
   **Binding D: flowID ↔ verifyRunID**
   - If `verifyRunID` provided, checks `storedVerifyRunID == requestVerifyRunID`
   - If mismatch: Reject with `"verifyRunID_mismatch"`

3. **If Any Binding Fails:**
   - Reject immediately with explicit reason
   - Do NOT attempt cryptographic verification
   - Do NOT return generic "DER verification failed"

4. **Decode Assertion:**
   - Decodes assertion CBOR map (0xa2)
   - Extracts `authenticatorData` (bstr, key 1 or "authenticatorData")
   - Extracts `signature` (bstr, key 2 or "signature", DER format)

5. **Dual DIGEST Verification Attempts:**
   
   **Attempt A (no re-hash):**
   ```swift
   let signedBytesA = authenticatorData + clientDataHash
   let digestA = SHA256.hash(data: signedBytesA)
   let isValidA = publicKey.isValidSignature(signatureDER, for: digestA)
   ```
   
   **Attempt B (re-hash clientDataHash):**
   ```swift
   let clientDataHashRehashed = SHA256.hash(data: clientDataHash)
   let signedBytesB = authenticatorData + clientDataHashRehashed
   let digestB = SHA256.hash(data: signedBytesB)
   let isValidB = publicKey.isValidSignature(signatureDER, for: digestB)
   ```
   
   **Accept if either attempt succeeds.**

6. **Logging:**
   - `[VERIFY_TRACE][TRANSPORT]` assertionObject.sha256
   - `[VERIFY_TRACE][CLIENT_DATA_HASH]` clientDataHash.sha256
   - `[VERIFY_TRACE][KEY_IDENTITY]` publicKeyX963.sha256, hex_prefix20, hex_suffix20, base64
   - `[VERIFY_TRACE][DECODED]` authenticatorData.sha256, signatureDER.sha256
   - `[VERIFY_TRACE][DER_SIGNATURE_FORENSICS]` r.hex, s.hex, lengths, padding info
   - `[VERIFY_TRACE][DIGESTS]` attemptA_signedBytes.sha256, attemptB_signedBytes.sha256
   - `[SIX_VALUES]` block matching frontend format:
     ```
     ---------- SIX_VALUES (verifyRunID=<uuid>) ----------
     authenticatorData.sha256=<hex>
     clientDataHash.sha256=<hex>
     signedBytes.sha256=<hex>
     signature.sha256=<hex>
     keyID_sha256=<hex>
     publicKeyX963.sha256=<hex>
     ----------
     ```
   - `[VERIFY_TRACE][RESULT]` verification outcome

7. **On Success:**
   - Mark `clientDataHash` as consumed
   - Return `{"status": "verified"}`

8. **On Failure:**
   - Do NOT consume hash (allow retry with new hash)
   - Return `{"status": "rejected", "reason": "..."}`

## Error Handling

### Safe Error Handling (No Crashes)

- **No `fatalError`:** All fatal errors replaced with logging and error returns
- **No `precondition`:** All preconditions replaced with `guard` statements returning errors
- **Explicit reasons:** All rejections include a `reason` field
- **Binding violations:** Reject immediately, do NOT attempt verification

### Error Response Format

All errors return `200 OK` with JSON body:
```json
{
  "status": "rejected",
  "reason": "<explicit error message>"
}
```

Common reasons:
- `"missing_flowID"` - flowID not provided
- `"flowID ↔ keyID binding violation"` - Binding A failed
- `"verifyRunID_mismatch"` - Binding D failed
- `"missing_hash"` - clientDataHash not found
- `"expired_hash"` - clientDataHash expired
- `"reused_hash"` - clientDataHash already consumed
- `"Public key not found for keyID"` - Public key not stored
- `"DER signature verification failed"` - Cryptographic verification failed

## Storage

### KeyStore (Public Keys)

- **Storage:** In-memory `[String: KeyStoreEntry]`
- **Key Format:** `"\(keyIDHex):\(flowID)"`
- **Entry Contains:**
  - `publicKey`: Data (65 bytes, X9.63 format)
  - `flowID`: String
  - `fingerprint`: PublicKeyFingerprint
  - `registeredAt`: Date
  - `source`: String

### ClientDataHashStore

- **Storage:** In-memory `[String: ClientDataHashEntry]`
- **Key Format:** `"\(keyIDHex):\(flowID)"`
- **Entry Contains:**
  - `clientDataHash`: Data (32 bytes)
  - `keyID`: Data
  - `flowID`: String
  - `verifyRunID`: String? (optional)
  - `generatedAt`: Date
  - `consumedAt`: Date? (set on consumption)
  - `used`: Bool

## Verification Logic

### Canonical Verifier

All verification goes through:
```swift
func verifyAssertion(
    publicKeyX963: Data,
    authenticatorData: Data,
    clientDataHash: Data,
    signatureDER: Data,
    logger: Logger
) throws -> Bool
```

Located in: `Sources/AppAttestBackend/Crypto/AppAttestAssertionVerifier.swift`

### Dual DIGEST Attempts

The verifier performs two attempts using DIGEST mode:
- **Attempt A:** No re-hash of clientDataHash
- **Attempt B:** Re-hash clientDataHash before concatenation

Both use: `publicKey.isValidSignature(signature, for: SHA256.Digest)`

**Why DIGEST mode:**
- Eliminates double-hashing confusion
- Makes the exact digest being verified explicit
- If both attempts fail, it's an identity mismatch, not a hashing issue

## Logging

### Structured Trace Logging

All critical boundary crossings are logged with structured `[VERIFY_TRACE]` blocks:

- `[VERIFY_TRACE][TRANSPORT]` - Assertion object integrity
- `[VERIFY_TRACE][CLIENT_DATA_HASH]` - Stored hash integrity
- `[VERIFY_TRACE][KEY_IDENTITY]` - Public key identity and lineage
- `[VERIFY_TRACE][DECODED]` - Decoded authenticatorData and signature
- `[VERIFY_TRACE][DER_SIGNATURE_FORENSICS]` - DER signature parsing details
- `[VERIFY_TRACE][DIGESTS]` - Both signedBytes attempts and digests
- `[VERIFY_TRACE][RESULT]` - Final verification outcome

### SIX_VALUES Block

Every verification request logs a `SIX_VALUES` block that must match the frontend's `SIX_VALUES` block byte-for-byte.

### Key Registration Logging

Every registration logs a `[KEY_REGISTERED]` block with:
- `publicKeyX963.sha256`
- `publicKeyX963.hex_prefix20`
- `publicKeyX963.hex_suffix20`
- `publicKeyX963.hex_full`
- `publicKeyX963.base64`

This enables key lineage verification at VERIFY time.

## Concurrency Safety

### KeyStore Deadlock Prevention

- **No nested sync:** Direct dictionary access within sync blocks
- **Debug guardrail:** `DispatchSpecificKey` detects re-entrancy in DEBUG builds
- **Safe error handling:** Logs errors instead of crashing

### ClientDataHashStore

- Uses separate `hashQueue` (no deadlock risk with KeyStore)
- Thread-safe via `DispatchQueue.sync`

## Testing

### Manual Test Flow

1. **REGISTER:**
   ```bash
   curl -X POST http://localhost:8080/app-attest/register \
     -H "Content-Type: application/json" \
     -d '{"keyID":"...","attestationObject":"..."}'
   ```
   Save `flowID` from response.

2. **CLIENT_DATA_HASH:**
   ```bash
   curl -X POST http://localhost:8080/app-attest/client-data-hash \
     -H "Content-Type: application/json" \
     -d '{"keyID":"...","flowID":"<from-register>"}'
   ```
   Save `clientDataHash` from response.

3. **VERIFY:**
   ```bash
   curl -X POST http://localhost:8080/app-attest/verify \
     -H "Content-Type: application/json" \
     -d '{"keyID":"...","flowID":"<from-register>","assertionObject":"..."}'
   ```

### Verification Checklist

- ✅ All bindings checked before verification
- ✅ SIX_VALUES logged for every verify request
- ✅ Dual DIGEST attempts performed
- ✅ No fatal errors or crashes
- ✅ Explicit rejection reasons
- ✅ Key lineage verified (REGISTER → VERIFY)

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

## Related Documentation

- `docs/README_VERIFICATION.md` - Documentation index
- `docs/AppAttest-ClientDataHash.md` - Complete authority contract
- `docs/ASSERTION_DER_VERIFICATION_FAILURE.md` - Verification approach
- `docs/APP_ATTEST_ASSERTION_VERIFICATION_GOTCHAS.md` - Common pitfalls
- `docs/KEYSTORE_DEADLOCK_SIGTRAP.md` - Deadlock bug and fix

---

**Last Updated:** 2026-01-17  
**Status:** Production-ready with safe error handling and comprehensive logging
