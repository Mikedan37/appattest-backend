# Observable Properties

This chapter describes measurable protocol behavior. These are observable facts about how the service operates, not security guarantees.

## Challenge Consumption

**Property**: Exactly one challenge may be consumed per (keyID, flowID) pair.

**This can be observed by:**
- Requesting a challenge for (keyID, flowID)
- Consuming the challenge successfully
- Attempting to consume the same challenge again
- Observing the second attempt returns status "rejected" with reason indicating reuse

**Property**: Expired challenges are rejected after 5 minutes (TTL).

**This can be observed by:**
- Requesting a challenge and noting the expiresAt timestamp
- Waiting more than 5 minutes
- Attempting to consume the challenge
- Observing the attempt returns status "rejected" with reason indicating expiration

**Property**: Consumed challenges cannot be reused (one-time-use).

**This can be observed by:**
- Consuming a challenge successfully
- Attempting to consume the same challenge again
- Observing the second attempt returns status "rejected" with reason indicating reuse

## Identity Bindings

**Property**: Binding A (flowID ↔ keyID) is enforced before verification.

**This can be observed by:**
- Registering a key with flowID X
- Attempting verification with flowID Y and the same keyID
- Observing verification is rejected before cryptographic verification is attempted

**Property**: Binding B (flowID ↔ challenge) is enforced before verification.

**This can be observed by:**
- Requesting a challenge for (keyID, flowID X)
- Attempting verification with flowID Y and the same challenge_id
- Observing verification is rejected before cryptographic verification is attempted

**Property**: Binding C (keyID ↔ publicKeyX963) is enforced during registration and verification.

**This can be observed by:**
- Registering with keyID that does not equal SHA256(publicKeyX963)
- Observing registration is rejected
- Attempting verification with mismatched keyID and publicKey
- Observing verification is rejected

**Property**: Binding D (flowID ↔ verifyRunID) is enforced if verifyRunID is provided.

**This can be observed by:**
- Requesting a challenge with verifyRunID X
- Attempting verification with verifyRunID Y
- Observing verification is rejected if verifyRunID mismatch

## Cryptographic Verification

**Property**: Signature verification performs at most two digest attempts (dual DIGEST-mode).

**This can be observed by:**
- Examining verification logs
- Observing at most two verification attempts are logged per request
- Both attempts use DIGEST mode (SHA256.Digest input)

**Property**: Signed bytes are constructed as: authenticatorData || clientDataHash.

**This can be observed by:**
- Examining verification logs
- Observing signedBytes_sha256 matches SHA256(authenticatorData || clientDataHash)
- Observing signedBytes_length equals authenticatorData_length + 32

**Property**: Nonce is computed as: SHA256(signedBytes).

**This can be observed by:**
- Examining verification logs
- Observing nonce_sha256 matches SHA256(signedBytes_sha256)
- Observing nonce_sha256 is 32 bytes

## Response Values

**Property**: Status field is either "verified" or "rejected".

**This can be observed by:**
- Making verification requests
- Examining response.status field
- Observing only these two values are returned

**Property**: "verified" means cryptographic verification and protocol-level bindings succeeded.

**This can be observed by:**
- Examining successful verification responses
- Observing status is "verified" when signature is valid and bindings are satisfied
- Observing status is "rejected" when signature is invalid or bindings fail

**Property**: "rejected" includes a reason field describing the failure.

**This can be observed by:**
- Making verification requests that fail
- Examining response.reason field
- Observing reason field is present and describes the failure type

## Storage

**Property**: Public keys are stored keyed by (keyID, flowID).

**This can be observed by:**
- Registering a key with (keyID, flowID)
- Observing the key can be retrieved using the same (keyID, flowID)
- Observing the key cannot be retrieved using different (keyID, flowID)

**Property**: Challenge entries are stored keyed by challenge_id, with flowKey (keyID, flowID) mapping.

**This can be observed by:**
- Requesting a challenge for (keyID, flowID)
- Observing the challenge can be retrieved using challenge_id
- Observing the challenge_id is mapped to the flowKey

**Property**: Storage is ephemeral (in-memory, reset on restart).

**This can be observed by:**
- Storing keys and challenges
- Restarting the service
- Observing stored keys and challenges are no longer available

## Important Note

These properties describe observable protocol behavior. They do not constitute security guarantees. See [Verification Semantics](./04-Verification-Semantics.md) for what "verified" means and does not provide.
