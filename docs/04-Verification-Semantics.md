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
- **Required**: Additional security layers must be implemented before granting access

### "rejected" Status

- **Meaning**: Cryptographic verification failed OR protocol-level binding violation OR structural validation failed
- **Reason field**: Provides specific failure reason

## Usage Requirements

Before granting access, you must implement:

1. Trust validation: Verify certificate chain, validate key source
2. Authorization: Check user permissions, access control
3. Policy enforcement: Validate bundle ID, team ID, environment
4. Additional freshness checks: If required beyond 5-minute TTL

See [Examples](./05-Examples.md) for usage patterns.
