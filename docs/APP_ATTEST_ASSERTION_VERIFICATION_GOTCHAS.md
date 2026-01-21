# App Attest Assertion Verification Gotchas

## Executive Summary

App Attest assertion verification is deceptively simple but fails in production due to three common gotchas:
1. **DER vs Raw signature format** (variable length, ASN.1 parsing)
2. **MESSAGE vs DIGEST mode** (double-hashing trap)
3. **Identity mismatches** (wrong key/clientDataHash/bytes masquerading as crypto failures)

This document explains why these bugs are common, how to avoid them, and the dual-attempt proof technique we use.

---

## Gotcha #1: DER vs Raw Signature Format

### The Problem

ECDSA signatures can be encoded in two formats:

1. **DER (Distinguished Encoding Rules)**: ASN.1-encoded `SEQUENCE { INTEGER r, INTEGER s }`
   - Variable length (typically 70-72 bytes for P-256, but can be 71, 73, etc.)
   - Starts with `0x30` (SEQUENCE tag)
   - Used by WebAuthn, App Attest, and most production systems

2. **Raw P1363**: 64-byte concatenation `r || s` (32 bytes each)
   - Fixed length: exactly 64 bytes
   - No ASN.1 structure
   - Used by some crypto libraries and test code

### Why This Causes Bugs

- **Apple frameworks hide DER parsing**: `SecKeyVerifySignature` handles DER internally, so iOS developers rarely see it
- **Backend engineers rarely parse ASN.1 manually**: Most assume "signature = 64 bytes" or "signature = 70 bytes"
- **Variable length is unexpected**: DER length depends on INTEGER padding, not just the signature values
- **API confusion**: CryptoKit has separate initializers for DER vs raw, and using the wrong one fails silently

### The Fix

```swift
// ✅ CORRECT: Detect DER by first byte, parse accordingly
guard signatureDER.first == 0x30 else {
    throw AppAttestVerificationError.invalidSignatureFormat
}
let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
```

**Rule**: If signature starts with `0x30`, it MUST be DER. No exceptions.

---

## Gotcha #2: MESSAGE vs DIGEST Mode (Double-Hashing Trap)

### The Problem

CryptoKit's `isValidSignature` has two overloads:

1. **MESSAGE mode**: `isValidSignature(_:for: Data)`
   - CryptoKit hashes the message internally with SHA256
   - Use when the signer also hashed internally

2. **DIGEST mode**: `isValidSignature(_:for: SHA256.Digest)`
   - CryptoKit uses the digest directly (no hashing)
   - Use when the signer signed a pre-computed digest

### Why This Causes Bugs

**The double-hashing trap:**

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

### Why It's Hard to Find

- **Unit tests pass**: If you control both signing and verification, MESSAGE mode works consistently
- **Logs look correct**: All byte-level hashes match, but verification still fails
- **API design is subtle**: Overloads differ only by type, not by name

### The Fix

**During debugging, use DIGEST mode ONLY:**

```swift
// Compute digest explicitly
let digest = SHA256.hash(data: signedBytes)

// Verify using DIGEST mode (no double-hashing)
let isValid = publicKey.isValidSignature(signature, for: digest)
```

**Rule**: Never use MESSAGE mode (`for: Data`) during debugging. It hides what you're actually verifying.

---

## Gotcha #3: Identity Mismatches (Wrong Key/ClientDataHash/Bytes)

### The Problem

If both verification attempts (A and B) fail, it's **not a hashing semantics issue**. It's an identity mismatch:
- Wrong public key (wrong cert, wrong representation, wrong parsing offset)
- Wrong clientDataHash (different challenge, expired, consumed)
- Wrong bytes (CBOR decoding error, byte truncation, encoding mismatch)

### Why This Masquerades as Crypto Failure

- **Error message is generic**: "Signature did not verify under the supplied public key"
- **All hashes match**: Frontend and backend fingerprints match, but verification fails
- **No obvious mismatch**: Everything "looks right" but isn't

### The Fix: Dual-Attempt Proof Technique

We use **dual DIGEST-mode attempts** to prove which signing theory is correct:

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

**If both fail:**
- It's not a hashing issue
- It's an identity mismatch (wrong key/clientDataHash/bytes)
- Log all intermediate values for forensic analysis

---

## Why This Bug Is Hard (Abstraction Boundary)

### The Abstraction Leak

App Attest signs a digest, but the API surface pretends you're signing messages. This mismatch causes 80% of App Attest bugs.

### Misleading Naming

- `clientDataHash` sounds terminal, but App Attest re-hashes it internally
- `isValidSignature(_:for: Data)` sounds like it takes "data", but it hashes internally
- Logs can lie: frontend logs show one thing, backend verifies another

### The Forensic Solution

1. **Backend-generated fingerprints only**: Don't trust frontend logs
2. **Dual attempts**: Prove which signing theory is correct
3. **Explicit logging**: Log all intermediate values (digests, signedBytes, etc.)
4. **Single canonical verifier**: No duplicate computation, no divergence

---

## The Canonical Rule

**Single verifier, backend-generated fingerprints only:**

1. All verification goes through `verifyAssertion()` in `AppAttestAssertionVerifier.swift`
2. `main.swift` must NOT recompute signedBytes or digests
3. Logs show both attempts' digests and results
4. If verification succeeds, logs state which attempt passed
5. If both fail, logs show enough to diagnose identity mismatch

---

## Code Locations

- **Canonical verifier**: `Sources/AppAttestBackend/Crypto/AppAttestAssertionVerifier.swift`
- **Route handler**: `Sources/AppAttestBackend/main.swift` (calls `verifyAssertion()` only)

---

## Related Documentation

- `docs/ASSERTION_DER_VERIFICATION_FAILURE.md` - Current verification approach
- `docs/DER_SIGNATURE_LENGTH_VARIABILITY.md` - Why DER lengths vary
- `docs/APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - MESSAGE vs DIGEST details
- `docs/KEYSTORE_DEADLOCK_SIGTRAP.md` - Storage deadlock bug

---

**Date:** 2026-01-17  
**Status:** Active - dual verification to determine correct signing theory
