# Verification Semantics

This chapter defines what a "verified" response means and what it does not provide.

## What "verified" Means

A `status: "verified"` response means:

1. **Cryptographic signature verification succeeded**: The ECDSA signature is valid for the observed byte sequence
2. **Protocol-level bindings satisfied**: All identity bindings (flowID ↔ keyID, flowID ↔ challenge, keyID ↔ publicKey) are satisfied
3. **Challenge consumption succeeded**: The challenge was consumed (one-time-use)
4. **Structural validation passed**: The assertion CBOR structure is valid, authenticatorData and signature are present

## What "verified" Does Not Provide

A `status: "verified"` response does not provide:

1. **Authorization**: The request is not authorized. Authorization checks must be implemented separately.
2. **Trust**: The device or key is not trusted. Trust validation (certificate chain verification) must be implemented separately.
3. **Policy compliance**: The assertion does not comply with policy. Policy enforcement (bundle ID, team ID checks) must be implemented separately.
4. **Freshness beyond TTL**: The assertion is not guaranteed fresh beyond the 5-minute challenge TTL. Additional freshness checks must be implemented if required.

## Response Format

```json
{
  "status": "verified" | "rejected",
  "reason": "<optional error message>"
}
```

### "verified" Status

- **Meaning**: Cryptographic verification and protocol-level enforcement succeeded
- **Does not provide**: Authorization, trust, or policy compliance
- **External concerns**: Additional security layers are external to this service

### "rejected" Status

- **Meaning**: Cryptographic verification failed OR protocol-level binding violation OR structural validation failed
- **Reason field**: Provides specific failure reason

## External Security Concerns

This service does not implement:

1. Trust validation: Certificate chain verification, key source validation
2. Authorization: User permissions, access control
3. Policy enforcement: Bundle ID, team ID, environment validation
4. Freshness validation: Replay protection beyond 5-minute challenge TTL

See [Security Composition](./06-Security-Composition.md) for integration patterns.
