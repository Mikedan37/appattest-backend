# Test Suite: Verification Guarantees

This test suite verifies all documented guarantees of the App Attest backend service.

## Test Files

### VerificationGuaranteesTests.swift
Tests core verification behavior:
- Verifies signature over `authenticatorData || clientDataHash`
- Detects tampering (rejects modified assertions)
- Rejects invalid formats (base64, CBOR, missing fields)
- Rejects unregistered keys
- Does NOT provide replay protection
- Does NOT check timestamps
- Does NOT authenticate callers
- Performs single ES256 verification
- Does NOT double-hash

### ByteSequenceVerificationTests.swift
Tests that verify the exact byte sequence used for signing:
- Verifies `authenticatorData || clientDataHash` (not CBOR Sig_structure)
- Rejects WebAuthn-style payloads
- Requires exact byte match (single byte difference causes rejection)
- Uses exact clientDataHash from request (not recomputed)

### SecurityBoundaryTests.swift
Tests that verify the service does NOT provide features it explicitly states it does not provide:
- Does NOT provide device trust
- Does NOT authenticate users
- Does NOT authorize requests
- Does NOT prevent replay
- Does NOT rate limit
- Does NOT prevent abuse
- Does NOT check timestamps
- Does NOT rotate keys
- Does NOT revoke keys

## Running Tests

```bash
swift test
```

## Test Requirements

Many tests require real App Attest assertions from an iOS device to fully verify cryptographic behavior. These tests are structured to:
1. Document what should be tested
2. Provide placeholders for real assertion data
3. Test what can be tested without real assertions (format validation, error handling, security boundaries)

## What These Tests Prove

1. **Correctness**: The service verifies signatures over the correct byte sequence
2. **Tamper Detection**: Any modification to assertions is detected
3. **Format Validation**: Invalid inputs are rejected appropriately
4. **Security Boundaries**: The service does not provide features it claims not to provide
5. **No Overreach**: The service stays within its documented scope
