# Protocol Flow

This chapter describes the complete three-endpoint verification flow from registration through verification.

## Overview

A verification flow consists of three sequential requests:

1. **Registration** - Extract and store public key, receive flowID
2. **Challenge Generation** - Request challenge, receive challenge_b64 and challenge_id
3. **Verification** - Verify assertion using stored key and challenge

## Registration

**Endpoint:** `POST /app-attest/register`

The frontend sends an attestation object. The backend:

- Extracts the public key from the attestation
- Validates keyID matches the public key (keyID == SHA256(publicKeyX963))
- Generates a flowID (UUID)
- Stores the public key keyed by (keyID, flowID)

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
  "status": "registered",
  "flowID": "<uuid>"
}
```

**Idempotency:** Multiple requests with the same `keyID` and `attestationObject` are allowed. Each request generates a new `flowID`.

## Challenge Generation

**Endpoint:** `GET /app-attest/challenge?keyID=<base64>&flowID=<uuid>`

The frontend requests a challenge. The backend:

- Generates a 32-byte random challenge
- Constructs clientDataJSON
- Computes clientDataHash = SHA256(clientDataJSON)
- Stores the challenge keyed by (keyID, flowID) with 5-minute TTL
- Returns challenge_b64, challenge_id, expiresAt

**Response:**
```json
{
  "challenge_b64": "<base64>",
  "challenge_id": "<uuid>",
  "expiresAt": "<ISO8601>"
}
```

**Write-once immutable:** Each `(keyID, flowID)` pair can have exactly one challenge. Subsequent requests return the existing challenge if it has not expired.

## Verification

**Endpoint:** `POST /app-attest/verify`

The frontend sends an assertion signed with the provided challenge. The backend:

- Enforces identity bindings
- Loads stored public key and challenge
- Extracts authenticatorData and signature from assertion
- Constructs signedBytes = authenticatorData || clientDataHash
- Verifies ECDSA signature over SHA256(signedBytes)
- Consumes the challenge

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "assertionObject_base64": "<base64>",
  "challenge_id": "<uuid>",
  "clientData_base64": "<base64>"
}
```

**Response:**
```json
{
  "status": "verified" | "rejected",
  "reason": "<optional>"
}
```

## Identity Bindings

The backend enforces four mandatory bindings before verification:

### Binding A: flowID ↔ keyID

The stored public key's flowID must match the request's flowID. Checked during VERIFY, after loading stored public key.

### Binding B: flowID ↔ challenge

The stored challenge must be bound to the request's flowID. Checked during VERIFY, when consuming challenge.

### Binding C: keyID ↔ publicKeyX963

The keyID must equal SHA256(publicKeyX963) exactly. Checked during REGISTER (validation) and VERIFY (assertion).

### Binding D: flowID ↔ verifyRunID

If verifyRunID is provided, it must match the stored verifyRunID for that flowID. Checked during VERIFY, when consuming challenge.

If any binding fails, verification is rejected before cryptographic verification is attempted.

## Challenge Consumption

The backend implements protocol-level replay protection via:

1. One-time-use challenges: Each challenge can only be consumed once
2. TTL expiration: Challenges expire after 5 minutes
3. Challenge consumption: Challenge is marked as consumed on successful verification

This provides protocol-level protection against immediate replay. It does not provide long-term freshness validation or additional policy-level replay protection.
