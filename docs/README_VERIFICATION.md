# App Attest Verification Documentation Index

## Core Documentation

1. **[AppAttest-ClientDataHash.md](./AppAttest-ClientDataHash.md)**
   - Complete authority contract
   - API specifications with flowID and verifyRunID
   - Failure triage guide
   - Anti-patterns
   - **Mandatory identity bindings (A, B, C, D)**

2. **[ASSERTION_DER_VERIFICATION_FAILURE.md](./ASSERTION_DER_VERIFICATION_FAILURE.md)**
   - Current verification approach (dual DIGEST attempts)
   - DER signature handling
   - MESSAGE vs DIGEST mode
   - Canonical verification function

4. **[APP_ATTEST_ASSERTION_VERIFICATION_GOTCHAS.md](./APP_ATTEST_ASSERTION_VERIFICATION_GOTCHAS.md)**
   - Why DER vs raw trips people
   - Why MESSAGE vs DIGEST trips people
   - Why identity mismatches masquerade as crypto failures
   - Dual-attempt proof technique
   - The canonical rule

## Technical Details

5. **[DER_SIGNATURE_LENGTH_VARIABILITY.md](./DER_SIGNATURE_LENGTH_VARIABILITY.md)**
   - Why DER signatures are variable length
   - ASN.1 INTEGER padding rules

6. **[KEYSTORE_DEADLOCK_SIGTRAP.md](./KEYSTORE_DEADLOCK_SIGTRAP.md)**
   - Storage deadlock bug and fix
   - **Safe error handling (no fatal errors)**

7. **[APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md](./APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md)**
   - MESSAGE vs DIGEST mode explanation

8. **[APP_ATTEST_ASSERTION_DIGEST_CONSTRUCTION.md](./APP_ATTEST_ASSERTION_DIGEST_CONSTRUCTION.md)**
   - clientDataHash re-hashing behavior

## The Complete Flow (Current Implementation)

### 1. REGISTER
- **Input:** `keyID` (base64), `attestationObject` (base64)
- **Backend:**
  - Decodes attestation object
  - Extracts public key (X9.63, 65 bytes, 0x04 prefix)
  - Validates `keyID == SHA256(publicKey)` (App Attest invariant)
  - Generates `flowID` (UUID)
  - Stores: `(keyID, flowID) → publicKeyX963`
  - Logs: `[KEY_REGISTERED]` with public key fingerprint
- **Response:** `{ "status": "registered", "flowID": "<uuid>" }`

### 2. CLIENT_DATA_HASH
- **Input:** `keyID` (base64), `flowID` (UUID), `verifyRunID` (optional UUID)
- **Backend:**
  - Validates `flowID` is not empty
  - Generates 32-byte challenge
  - Builds `clientDataJSON`
  - Computes `clientDataHash = SHA256(clientDataJSON)`
  - Stores: `(keyID, flowID) → { clientDataHash, verifyRunID, expiresAt, used }`
  - Logs: `[CLIENT_DATA_HASH]` with hash and verifyRunID
- **Response:** `{ "clientDataHash": "<base64>", "expiresAt": "<ISO8601>" }`

### 3. VERIFY
- **Input:** `keyID` (base64), `flowID` (UUID), `assertionObject` (base64), `verifyRunID` (optional UUID)
- **Backend:**
  - **Binding checks (BEFORE verification):**
    - **Binding A:** `flowID ↔ keyID` (stored flowID == request flowID)
    - **Binding B:** `flowID ↔ clientDataHash` (validated via consumeClientDataHash)
    - **Binding C:** `keyID ↔ publicKeyX963` (keyID == SHA256(publicKey))
    - **Binding D:** `flowID ↔ verifyRunID` (if verifyRunID provided)
  - Loads stored `clientDataHash` (consumes on success)
  - Loads stored `publicKeyX963`
  - Decodes assertion CBOR
  - Extracts `authenticatorData` and `signatureDER`
  - **Dual DIGEST verification attempts:**
    - **Attempt A:** `SHA256(authenticatorData || clientDataHash)`
    - **Attempt B:** `SHA256(authenticatorData || SHA256(clientDataHash))`
  - Logs: `[SIX_VALUES]` block matching frontend format
  - Returns: `{ "status": "verified" | "rejected", "reason": "<optional>" }`

## Mandatory Identity Bindings

The backend **MUST** check these bindings **BEFORE** attempting cryptographic verification:

- **Binding A:** `flowID ↔ keyID` - The stored public key's flowID must match the request flowID
- **Binding B:** `flowID ↔ clientDataHash` - The stored clientDataHash must be bound to the request flowID
- **Binding C:** `keyID ↔ publicKeyX963` - The keyID must equal SHA256(publicKey) exactly
- **Binding D:** `flowID ↔ verifyRunID` - If verifyRunID is provided, it must match the stored verifyRunID

**If any binding fails, reject with explicit reason. Do NOT attempt verification.**

## SIX_VALUES Logging

The backend logs a `SIX_VALUES` block for every verification request:

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

These values **MUST** match the frontend's `SIX_VALUES` block byte-for-byte. If they don't, it's an identity drift issue, not a cryptographic failure.

## Error Handling

- **No fatal errors:** All errors are logged and returned to the client
- **No crashes:** Invalid inputs return rejection responses, not crashes
- **Explicit reasons:** All rejections include a `reason` field explaining why

## Quick Start

1. Read `AppAttest-ClientDataHash.md` for the complete contract
2. Review `ASSERTION_DER_VERIFICATION_FAILURE.md` for current verification approach
3. Check `KEYSTORE_DEADLOCK_SIGTRAP.md` for concurrency safety
4. See `docs/README.md` for the complete documentation index

## The Model (TL;DR)

- **Backend owns:** clientDataHash generation, storage, verification
- **Backend owns:** Public key storage (keyed by `(keyID, flowID)`)
- **Backend enforces:** All identity bindings before verification
- **Frontend owns:** Request hash, use verbatim, sign, transport
- **Apple signs:** `authenticatorData || clientDataHash` (or `authenticatorData || SHA256(clientDataHash)`)
- **Backend verifies:** Dual DIGEST attempts to prove correct signing semantics

**No recomputation. No guessing. No shared authority. No silent failures.**
