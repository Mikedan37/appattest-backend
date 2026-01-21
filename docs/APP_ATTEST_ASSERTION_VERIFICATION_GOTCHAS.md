# App Attest Assertion Verification Gotchas

## Overview

App Attest assertion verification can fail due to three common issues:
1. **DER vs Raw signature format** (variable length, ASN.1 parsing)
2. **MESSAGE vs DIGEST mode** (double-hashing trap)
3. **Identity mismatches** (wrong key/clientDataHash/bytes masquerading as crypto failures)

## Gotcha #1: DER vs Raw Signature Format

### Signature Formats

ECDSA signatures can be encoded in two formats:

1. **DER (Distinguished Encoding Rules)**: ASN.1-encoded `SEQUENCE { INTEGER r, INTEGER s }`
   - Variable length (typically 70-72 bytes for P-256, but can be 71, 73, etc.)
   - Starts with `0x30` (SEQUENCE tag)
   - Used by WebAuthn, App Attest, and most production systems

2. **Raw P1363**: 64-byte concatenation `r || s` (32 bytes each)
   - Fixed length: exactly 64 bytes
   - No ASN.1 structure
   - Used by some crypto libraries and test code

### Detection

```swift
// ✅ CORRECT: Detect DER by first byte, parse accordingly
guard signatureDER.first == 0x30 else {
    throw AppAttestVerificationError.invalidSignatureFormat
}
let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
```

**Rule**: If signature starts with `0x30`, it is DER. No exceptions.

## Gotcha #2: MESSAGE vs DIGEST Mode (Double-Hashing Trap)

### Verification Modes

CryptoKit's `isValidSignature` has two overloads:

1. **MESSAGE mode**: `isValidSignature(_:for: Data)`
   - CryptoKit hashes the message internally with SHA256
   - Used when the signer also hashed internally

2. **DIGEST mode**: `isValidSignature(_:for: SHA256.Digest)`
   - CryptoKit uses the digest directly (no hashing)
   - Used when the signer signed a pre-computed digest

### The Double-Hashing Trap

```swift
// ❌ WRONG: Causes double-hashing
let signedBytes = authenticatorData + clientDataHash
let digest = SHA256.hash(data: signedBytes)
let isValid = publicKey.isValidSignature(signature, for: Data(digest))
// CryptoKit hashes Data(digest) again → SHA256(SHA256(signedBytes)) → FAILS
```

```swift
// ✅ CORRECT: DIGEST mode, no double-hashing
let signedBytes = authenticatorData + clientDataHash
let digest = SHA256.hash(data: signedBytes)
let isValid = publicKey.isValidSignature(signature, for: digest)
// CryptoKit uses digest directly → SHA256(signedBytes) → SUCCEEDS
```

**Rule**: Use DIGEST mode (`for: SHA256.Digest`). Never use MESSAGE mode (`for: Data`) during verification.

## Gotcha #3: Identity Mismatches (Wrong Key/ClientDataHash/Bytes)

If both verification attempts (A and B) fail, it is not a hashing semantics issue. It is an identity mismatch:
- Wrong public key (wrong cert, wrong representation, wrong parsing offset)
- Wrong clientDataHash (different challenge, expired, consumed)
- Wrong bytes (CBOR decoding error, byte truncation, encoding mismatch)

### Dual-Attempt Proof Technique

The verifier uses dual DIGEST-mode attempts to determine which signing theory is correct:

**Attempt A (no re-hash):**
```swift
let signedBytesA = authenticatorData + clientDataHash
let digestA = SHA256.hash(data: signedBytesA)
let isValidA = publicKey.isValidSignature(signature, for: digestA)
```

**Attempt B (re-hash clientDataHash):**
```swift
let clientDataHashRehashed = SHA256.hash(data: clientDataHash)
let signedBytesB = authenticatorData + clientDataHashRehashed
let digestB = SHA256.hash(data: signedBytesB)
let isValidB = publicKey.isValidSignature(signature, for: digestB)
```

If both fail:
- It is not a hashing issue
- It is an identity mismatch (wrong key/clientDataHash/bytes)
- Log all intermediate values for forensic analysis

## The Canonical Rule

**Single verifier, backend-generated fingerprints only:**

1. All verification goes through `verifyAssertion()` in `AppAttestAssertionVerifier.swift`
2. `main.swift` does not recompute signedBytes or digests
3. Logs show both attempts' digests and results
4. If verification succeeds, logs state which attempt passed
5. If both fail, logs show enough to diagnose identity mismatch

## Code Locations

- **Canonical verifier**: `Sources/AppAttestBackend/Crypto/AppAttestAssertionVerifier.swift`
- **Route handler**: `Sources/AppAttestBackend/main.swift` (calls `verifyAssertion()` only)

## Related Documentation

- `docs/ASSERTION_DER_VERIFICATION_FAILURE.md` - Verification approach
- `docs/DER_SIGNATURE_LENGTH_VARIABILITY.md` - Why DER lengths vary
- `docs/APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - MESSAGE vs DIGEST details
- `docs/KEYSTORE_DEADLOCK_SIGTRAP.md` - Storage concurrency safety
