# Integrating Verification into a Secure System

This chapter describes how to compose this verification service with trust validation, authorization, and policy enforcement.

## Conceptual Composition

This service performs cryptographic verification only. Trust, authorization, freshness, and policy are external concerns that must be implemented separately.

## Security Layers

### Layer 1: Cryptographic Verification (This Service)

- Verifies ECDSA signature validity
- Enforces protocol-level identity bindings
- Validates assertion structure
- Consumes challenges (one-time-use)

### Layer 2: Trust Validation (External)

- Certificate chain verification
- Key source validation
- Certificate revocation checks

### Layer 3: Authorization (External)

- User permissions
- Access control
- Role-based authorization

### Layer 4: Policy Enforcement (External)

- Bundle ID validation
- Team ID validation
- Environment restrictions

### Layer 5: Freshness Validation (External)

- Replay protection beyond 5-minute challenge TTL
- Timestamp validation
- Nonce tracking

## Composition Example

```swift
// Step 1: Cryptographic verification (this service)
let verifyResponse = try await httpClient.post("/app-attest/verify", body: verifyRequest)
let result = try JSONDecoder().decode(VerifyResponse.self, from: verifyResponse.data)

guard result.status == "verified" else {
    return .unauthorized
}

// Step 2: Trust validation (external)
guard let attestationObject = Data(base64Encoded: assertionObjectBase64) else {
    return .badRequest
}
guard validateCertificateChain(attestationObject: attestationObject) else {
    return .unauthorized
}

// Step 3: Authorization (external)
guard let user = getCurrentUser(),
      isAuthorized(user: user, keyID: keyID) else {
    return .forbidden
}

// Step 4: Policy enforcement (external)
guard let bundleID = extractBundleID(from: attestationObject),
      let teamID = extractTeamID(from: attestationObject),
      validatePolicy(bundleID: bundleID, teamID: teamID) else {
    return .forbidden
}

// Step 5: Additional freshness checks (external, if required)
guard isFresh(assertionTimestamp: extractTimestamp(from: attestationObject)) else {
    return .unauthorized
}

// All checks passed
grantAccess()
```

## Service Boundaries

This service does not implement:
- Certificate chain verification
- Authorization logic
- Policy enforcement
- Freshness validation beyond challenge TTL

These concerns must be layered separately.
