# App Attest Assertion Verification: Digest Construction

## Digest Construction Requirements

Successful ECDSA verification requires computing the message digest using:

```
messageDigest = SHA256(authenticatorData || SHA256(clientDataHashBytes))
```

Where `clientDataHashBytes` is the 32-byte value used alongside `authenticatorData` in the assertion flow.

Verifying against:

```
SHA256(authenticatorData || clientDataHashBytes)
```

fails deterministically, even when:
- the stored public key is correct (`keyID == SHA256(pubKeyX9.63)`)
- `rpIdHash` is correct
- the signature DER parses cleanly
- verification uses CryptoKit DIGEST mode (no implicit hashing)

## Digest Construction Contract

### What App Attest Signs

App Attest signs a SHA256 digest, not raw message bytes. The digest is constructed as:

```
messageDigest = SHA256(authenticatorData || SHA256(clientDataHashBytes))
```

Then signed with ECDSA P-256:

```
ECDSA_sign(messageDigest, privateKey)
```

### Why clientDataHashBytes Must Be Re-Hashed

In this implementation, the assertion signature validates only when the backend:

1. Re-hashes `clientDataHashBytes` (the 32-byte value)
2. Appends that 32-byte digest to `authenticatorData`
3. Hashes the final buffer and verifies the ECDSA signature against that digest

**Effective operation:**

```swift
let clientDataHashRehashed = SHA256.hash(data: clientDataHashBytes)
let signedBytes = authenticatorData + clientDataHashRehashed
let messageDigest = SHA256.hash(data: signedBytes)
let isValid = publicKey.isValidSignature(signatureDER, for: messageDigest) // DIGEST mode
```

## Reproduction Test

Compute two candidate digests:

```swift
// Expected to FAIL
let wrongDigest = SHA256.hash(data: authenticatorData + clientDataHashBytes)

// Expected to PASS
let correctDigest = SHA256.hash(
    data: authenticatorData + SHA256.hash(data: clientDataHashBytes)
)
```

**Expected result:**
- `wrongDigest` → verification fails
- `correctDigest` → verification succeeds

## Correct Verification Procedure

```swift
// Step 1: Re-hash clientDataHashBytes
let clientDataHashRehashed = SHA256.hash(data: clientDataHashBytes)

// Step 2: Construct signed bytes
let signedBytes = authenticatorData + clientDataHashRehashed

// Step 3: Compute final digest
let messageDigest = SHA256.hash(data: signedBytes)

// Step 4: Verify signature (DIGEST mode - no double-hashing)
let isValid = publicKey.isValidSignature(signatureDER, for: messageDigest)
```

### Incorrect (Will Always Fail)

```swift
let signedBytes = authenticatorData + clientDataHashBytes
let digest = SHA256.hash(data: signedBytes)
publicKey.isValidSignature(signatureDER, for: digest)
```

## Code Location

**Implementation:** `Sources/AppAttestBackend/main.swift` lines ~2212-2225

**Key Code:**
```swift
// Required for App Attest assertion verification flow:
let clientDataHashHashed = SHA256.hash(data: clientDataHashData)
let signedBytes = authenticatorData + clientDataHashHashed
let messageDigest = SHA256.hash(data: signedBytes)
```

## Related Documentation

- `APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - MESSAGE vs DIGEST mode (CryptoKit API gotcha)
- `DER_SIGNATURE_LENGTH_VARIABILITY.md` - DER signature length variability
- `AppAttest-ClientDataHash.md` - Backend-owned clientDataHash model

## Testing

Verification behavior:
- Verification succeeds deterministically
- Diagnostic logs show `old_messageDigest_sha256` (wrong) vs `new_messageDigest_sha256` (correct)
- Only the correct digest path verifies successfully

## Notes

This document describes behavior observed in the end-to-end App Attest assertion flow via forensic logs and digest A/B verification. Apple's public docs do not explicitly describe this exact construction.

This is an empirically required construction for this implementation. Other implementations may differ, but this is what works in end-to-end tests.

## For Future Contributors

If you see code that constructs `signedBytes` as:

```swift
let signedBytes = authenticatorData + clientDataHashBytes  // WRONG
```

**STOP.** This is incorrect for this flow. It must be:

```swift
let clientDataHashHashed = SHA256.hash(data: clientDataHashBytes)
let signedBytes = authenticatorData + clientDataHashHashed  // CORRECT
```

This is not optional. This is what end-to-end tests require.
