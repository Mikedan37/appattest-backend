# Implementation Details

This chapter describes the current implementation specifics.

## Endpoints

### POST /app-attest/register

Extracts and stores a public key from an App Attest attestation object.

**Request:**
```json
{
  "keyID": "<base64>",
  "attestationObject": "<base64>",
  "clientDataHash_base64": "<base64>"
}
```

**Response:**
```json
{
  "status": "registered" | "rejected",
  "reason": "<optional>",
  "flowID": "<uuid>"
}
```

**Behavior:**
- Validates `keyID == SHA256(publicKeyX963)` (App Attest invariant)
- Validates nonce using `clientDataHash_base64`:
  - `clientDataHash = SHA256(challenge)`
  - `nonce = SHA256(authenticatorData || clientDataHash)`
  - nonce must match certificate extension `1.2.840.113635.100.8.2`
- Generates and returns `flowID` (UUID)
- Stores `(keyID, flowID) → publicKeyX963`

**Idempotency:** Multiple requests with the same `keyID` and `attestationObject` are allowed. Each request generates a new `flowID`.

### GET /app-attest/challenge

Generates and stores a challenge bound to `(keyID, flowID)`.

**Request:** Query parameters
- `keyID`: Base64-encoded keyID
- `flowID`: UUID flowID

**Response:**
```json
{
  "challenge_b64": "<base64>",
  "challenge_id": "<uuid>",
  "expiresAt": "<ISO8601>"
}
```

**Behavior:**
- Generates 32-byte cryptographically random challenge
- Builds canonical `clientDataJSON`
- Computes `clientDataHash = SHA256(clientDataJSON)`
- Stores challenge keyed by challenge_id with:
  - challenge: 32 bytes
  - challenge_id: UUID
  - keyID: 32 bytes
  - flowID: UUID
  - expiresAt: timestamp + 5 minutes
  - used: false (one-time-use flag)
- Returns `challenge_b64`, `challenge_id`, `expiresAt`

**Write-once immutable:** Each `(keyID, flowID)` pair can have exactly one challenge. Subsequent requests return the existing challenge if it has not expired.

### POST /app-attest/verify

Verifies an assertion signature using stored challenge and `publicKeyX963`.

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "assertionObject_base64": "<base64>",
  "challenge_id": "<uuid>",
  "clientData_base64": "<base64>",
  "verifyRunID": "<optional-uuid>"
}
```

**Response:**
```json
{
  "status": "verified" | "rejected",
  "reason": "<optional>"
}
```

**Behavior:**
1. Enforces identity bindings (A, B, C, D) before verification
2. Loads stored challenge for `(keyID, flowID)` (consumes on success)
3. Loads stored `publicKeyX963` for `(keyID, flowID)`
4. Decodes assertion CBOR to extract `authenticatorData` and `signatureDER`
5. Performs dual DIGEST verification attempts
6. Logs `[SIX_VALUES]` block matching frontend format
7. Returns verification result

## Storage

**KeyStore (Public Keys):**
- Storage: In-memory `[String: KeyStoreEntry]` (ephemeral, reset on restart)
- Key format: `"\(keyIDHex):\(flowID)"`
- Entry: `{ publicKey: Data, flowID: String, fingerprint: PublicKeyFingerprint, ... }`

**ChallengeStore:**
- Storage: In-memory `[String: ChallengeEntry]` (ephemeral, reset on restart)
- Key format: challenge_id (UUID)
- Mapping: flowKey (keyID, flowID) → challenge_id
- Entry: `{ challenge: Data, challengeID: String, keyID: Data, flowID: String, expiresAt: Date, used: Bool, ... }`

Storage is intentionally abstracted. Replace with persistent storage (database, filesystem, key management service) as needed.

## Verification Modes

Select via environment variable `APP_ATTEST_ASSERTION_MODE`: `strict` or `s` for STRICT, `opaque` or `o` for OPAQUE. Default is STRICT.

| Mode | ECDSA gate | When to use |
|------|------------|-------------|
| **STRICT** | `nonce = SHA256(authenticatorData \|\| clientDataHash)`; reject if `isValidSignature(sig, for: nonce)` is false | Production when CryptoKit verification works on your stack |
| **OPAQUE** | ECDSA is logged only; accept when structural checks pass (keyID, flowID, challenge, signCount monotonic, rpIdHash, structural sanity) | When STRICT rejects valid assertions and forensic logs show byte-identical inputs (CryptoKit/App Attest quirks on some platforms) |

**Pipeline (both modes):**  
`signedBytes = authenticatorData || clientDataHash`, `nonce = SHA256(signedBytes)`.  
ECDSA: `isValidSignature(sig, for: nonce)` (DIGEST, gate in STRICT); `isValidSignature(sig, for: signedBytes)` (MESSAGE, diagnostic only).  
SignCount must be strictly monotonic per key; `VERIFICATION_CANONICAL` is logged once per `verifyRunID`.

**What is verified:** keyID↔publicKey, flowID binding, challenge (server-issued, single-use, not expired), signCount monotonic, rpIdHash, CBOR/signature structure; in STRICT, ECDSA(nonce).

**What is not verified:** whether the assertion is recent, reused, or authorized.
