# Examples

This chapter provides minimal API usage examples.

## Minimal Example

```swift
let response = try await httpClient.post("/app-attest/verify", body: request)
let result = try JSONDecoder().decode(VerifyResponse.self, from: response.data)

switch result.status {
case "verified":
    // Signature is cryptographically valid for observed bytes
    break
case "rejected":
    throw VerificationError.rejected
}
```

This example demonstrates cryptographic verification only. Trust, authorization, freshness, and policy are external concerns.

## API Usage Patterns

### Register Endpoint

```swift
let registerRequest = RegisterRequest(
    keyID: keyIDBase64,
    attestationObject: attestationObjectBase64
)

let response = try await httpClient.post("/app-attest/register", body: registerRequest)
let result = try JSONDecoder().decode(RegisterResponse.self, from: response.data)

let flowID = result.flowID
```

### Client Data Hash Endpoint

```swift
let hashRequest = ClientDataHashRequest(
    keyID: keyIDBase64,
    flowID: flowID
)

let response = try await httpClient.post("/app-attest/client-data-hash", body: hashRequest)
let result = try JSONDecoder().decode(ClientDataHashResponse.self, from: response.data)

let clientDataHash = result.clientDataHash
let expiresAt = result.expiresAt
```

### Verify Endpoint

```swift
let verifyRequest = VerifyRequest(
    keyID: keyIDBase64,
    flowID: flowID,
    assertionObject: assertionObjectBase64,
    verifyRunID: verifyRunID
)

let response = try await httpClient.post("/app-attest/verify", body: verifyRequest)
let result = try JSONDecoder().decode(VerifyResponse.self, from: response.data)

switch result.status {
case "verified":
    // Cryptographic verification succeeded
    break
case "rejected":
    // Verification failed: result.reason contains details
    throw VerificationError.rejected(result.reason)
}
```

## Response Fields

### RegisterResponse

- `status`: "registered" | "rejected"
- `flowID`: UUID string
- `reason`: Optional error message

### ClientDataHashResponse

- `clientDataHash`: Base64-encoded 32-byte hash
- `expiresAt`: ISO8601 timestamp

### VerifyResponse

- `status`: "verified" | "rejected"
- `reason`: Optional error message

## Anti-Patterns

### Using "verified" as Authorization Gate

```swift
if result.status == "verified" {
    grantAccess() // Anti-pattern: No authorization check
}
```

**Consequence**: A "verified" response indicates cryptographic validity only. Authorization checks must be implemented separately.

**Correction**: Implement authorization checks before granting access.

### Accepting Client-Provided Hash

```swift
struct VerifyRequest {
    let keyID: String
    let assertionObject: String
    let clientDataHash: String  // Anti-pattern: Remove this field
}
```

**Consequence**: Client could supply a different hash than what was issued, breaking replay protection.

**Correction**: Backend generates and stores the hash. Client never provides it.

### Using Different flowID Across Endpoints

```swift
let flowID1 = register()  // Returns flowID: "ABC-123"
let hash = clientDataHash(flowID: "XYZ-789")  // Anti-pattern: Different flowID
verify(flowID: "XYZ-789")  // Anti-pattern: Binding violation
```

**Consequence**: flowID binds keyID, clientDataHash, and publicKey together. Using different flowIDs breaks bindings.

**Correction**: Reuse the same flowID across all three endpoints in a single flow.

### Attempting Verification Before Binding Checks

```swift
let isValid = verifySignature(...)  // Anti-pattern: Check bindings first
if storedFlowID != requestFlowID { ... }  // Too late
```

**Consequence**: Binding violations should be caught immediately, not after expensive cryptographic operations.

**Correction**: Enforce all identity bindings before attempting cryptographic verification.
