# Examples

This chapter provides usage examples showing correct and incorrect patterns.

## Minimal Example

This example shows the minimal code required to verify an assertion.

```swift
// Step 1: Request challenge
let challengeResponse = try await httpClient.get(
    "/app-attest/challenge?keyID=\(keyIDBase64)&flowID=\(flowID)"
)
let challengeData = try JSONDecoder().decode(ChallengeResponse.self, from: challengeResponse.data)
let challengeBase64 = challengeData.challenge_b64
let challengeID = challengeData.challenge_id

// Step 2: Construct clientDataJSON and clientDataHash
let clientDataJSON = """
{
    "type": "apple-appattest",
    "challenge": "\(challengeBase64)",
    "origin": "\(bundleID)"
}
""".data(using: .utf8)!
let clientDataHash = Data(SHA256.hash(data: clientDataJSON))
let clientDataBase64 = clientDataJSON.base64EncodedString()

// Step 3: Generate assertion (on device, using clientDataHash)
// ... assertion generation code ...

// Step 4: Verify assertion
let verifyRequest = VerifyRequest(
    keyID: keyIDBase64,
    flowID: flowID,
    assertionObject_base64: assertionObjectBase64,
    challenge_id: challengeID,
    clientData_base64: clientDataBase64
)

let verifyResponse = try await httpClient.post("/app-attest/verify", body: verifyRequest)
let result = try JSONDecoder().decode(VerifyResponse.self, from: verifyResponse.data)

if result.status == "verified" {
    // Note: This example shows verification only.
    // Production code must implement:
    // - Trust validation (certificate chain verification)
    // - Authorization (access control checks)
    // - Policy enforcement (bundle ID, team ID validation)
    // See Verification Semantics for details.
    
    if knownKeyIDs.contains(keyID) {
        grantAccess()
    } else {
        return .unauthorized
    }
} else {
    return .unauthorized
}
```

**What this example does:**
- Requests challenge from backend
- Constructs clientDataHash from challenge
- Verifies cryptographic signature
- Checks protocol-level bindings
- Grants access if keyID is known

**What this example does not do:**
- Validate certificate chain
- Check authorization
- Enforce policy (bundle ID, team ID)
- Validate freshness beyond 5-minute TTL

## Correct Full Usage

This example shows complete security flow with all required checks.

```swift
// Step 1-3: Same as minimal example (request challenge, construct clientDataHash, generate assertion)

// Step 4: Verify assertion
let verifyResponse = try await httpClient.post("/app-attest/verify", body: verifyRequest)
let result = try JSONDecoder().decode(VerifyResponse.self, from: verifyResponse.data)

guard result.status == "verified" else {
    return .unauthorized
}

// Step 5: Trust validation (required)
// Validate certificate chain from attestation object
guard let attestationObject = Data(base64Encoded: assertionObjectBase64) else {
    return .badRequest
}
guard validateCertificateChain(attestationObject: attestationObject) else {
    return .unauthorized
}

// Step 6: Authorization (required)
// Check user permissions and access control
guard let user = getCurrentUser(),
      isAuthorized(user: user, keyID: keyID) else {
    return .forbidden
}

// Step 7: Policy enforcement (required)
// Validate bundle ID, team ID, environment
guard let bundleID = extractBundleID(from: attestationObject),
      let teamID = extractTeamID(from: attestationObject),
      validatePolicy(bundleID: bundleID, teamID: teamID) else {
    return .forbidden
}

// Step 8: Additional freshness checks (if required)
guard isFresh(assertionTimestamp: extractTimestamp(from: assertionObject)) else {
    return .unauthorized
}

// Step 9: All checks passed - grant access
grantAccess()
```

**What this example does:**
- Verifies cryptographic signature
- Validates certificate chain
- Checks authorization
- Enforces policy
- Validates freshness

**What this example does not do:**
- Rely solely on "verified" status for security decisions

## Incorrect Usage

### Using "verified" as Authorization Gate

```swift
// Incorrect: Using "verified" as authorization gate
let verifyResponse = try await httpClient.post("/app-attest/verify", body: verifyRequest)
let result = try JSONDecoder().decode(VerifyResponse.self, from: verifyResponse.data)

if result.status == "verified" {
    grantAccess() // Incorrect: No authorization check
}
```

**What this example does:**
- Verifies cryptographic signature
- Grants access based solely on verification

**What this example does not do:**
- Check authorization
- Validate trust
- Enforce policy

**Problem**: A "verified" response does not provide authorization. Authorization checks must be implemented separately.

**Fix**: Add authorization checks before granting access. See "Correct Full Usage" example above.

### Accepting Client-Provided Hash

```swift
// Incorrect: Backend must never accept hash from client
struct VerifyRequest {
    let keyID: String
    let assertionObject: String
    let clientDataHash: String  // Incorrect - remove this field
}
```

**Problem**: Client could supply a different hash than what was issued, breaking replay protection.

**Fix**: Backend generates and stores the hash. Client never provides it.

### Using Different flowID Across Endpoints

```swift
// Incorrect: flowID must be reused
let flowID1 = register()  // Returns flowID: "ABC-123"
let hash = clientDataHash(flowID: "XYZ-789")  // Incorrect - different flowID
verify(flowID: "XYZ-789")  // Incorrect - binding violation
```

**Problem**: flowID binds keyID, clientDataHash, and publicKey together. Using different flowIDs breaks bindings.

**Fix**: Reuse the same flowID across all three endpoints in a single flow.

### Attempting Verification Before Binding Checks

```swift
// Incorrect: Check bindings first
let isValid = verifySignature(...)  // Incorrect - check bindings first
if storedFlowID != requestFlowID { ... }  // Too late
```

**Problem**: Binding violations should be caught immediately, not after expensive cryptographic operations.

**Fix**: Enforce all identity bindings before attempting cryptographic verification.
