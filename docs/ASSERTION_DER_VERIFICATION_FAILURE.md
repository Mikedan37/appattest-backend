# Assertion DER Verification Failure

## Summary

App Attest assertion verification was failing with "DER signature verification failed" even though frontend and backend fingerprints for `authenticatorData`, `clientDataHash`, and `signedBytes_sha256` matched exactly.

**Current status:** Implementing dual verification attempts (A and B) using DIGEST mode to prove which signing theory is correct. Once we determine which attempt succeeds, we'll consolidate to a single canonical path.

## Why DER vs Raw Signatures is a Common Bug

ECDSA signatures can be encoded in two formats:

1. **DER (Distinguished Encoding Rules)**: ASN.1-encoded SEQUENCE { INTEGER r, INTEGER s }
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

## Why MESSAGE vs DIGEST Mode Matters

CryptoKit's `isValidSignature` has two overloads:

1. **MESSAGE mode**: `isValidSignature(_:for: Data)`
   - CryptoKit hashes the message internally with SHA256
   - Use when the signer also hashed internally (App Attest)

2. **DIGEST mode**: `isValidSignature(_:for: SHA256.Digest)`
   - CryptoKit uses the digest directly (no hashing)
   - Use when the signer signed a pre-computed digest (WebAuthn)

### Current Approach: Dual Verification to Prove Signing Theory

We're currently testing two signing theories using DIGEST mode (to eliminate hashing confusion):

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

**Why DIGEST mode during debugging:**
- Eliminates double-hashing confusion
- Makes the exact digest being verified explicit
- If both attempts fail, it's not a hashing semantics issue - it's identity (wrong key/clientDataHash/bytes)

Once we determine which attempt succeeds, we'll consolidate to a single canonical path.

## The Exact Canonical Rule We Enforce

### Single Verification Function

All App Attest verification must use:

```swift
func verifyAssertion(
    publicKeyX963: Data,
    authenticatorData: Data,
    clientDataHash: Data,
    signatureDER: Data,
    logger: Logger
) throws -> Bool
```

### Hard Requirements

1. **Signature must be DER**: If signature starts with `0x30`, it MUST use `derRepresentation` initializer
2. **Public key from X9.63**: `P256.Signing.PublicKey(x963Representation:)` (65 bytes, `0x04` prefix)
3. **Dual verification during debugging**: Test both signing theories using DIGEST mode to prove which is correct
4. **Once proven**: Consolidate to single canonical path based on which attempt succeeds

### Guardrails

- **DIGEST mode during debugging**: Use DIGEST mode to eliminate hashing confusion and prove which signing theory is correct
- **Signature format**: If signature starts with `0x30` but doesn't parse as DER, fail loudly
- **DER only**: No "try both DER and raw" fallbacks - DER is required
- **If both attempts fail**: It's not a hashing issue - it's identity (wrong key/clientDataHash/bytes)

## How This Prevents Regressions

1. **Single canonical function**: All verification goes through one function
2. **Hard guardrails**: Compile-time and runtime checks prevent wrong API usage
3. **Explicit logging**: `VERIFICATION_DUAL_ATTEMPT` block shows both attempts with all intermediate values
4. **No fallbacks**: If DER parsing fails, verification fails - no silent fallback to raw

## Code Location

- **Canonical verifier**: `Sources/AppAttestBackend/Crypto/AppAttestAssertionVerifier.swift`
- **Route handler**: `Sources/AppAttestBackend/main.swift` (calls `verifyAssertion()` only)

## Related Documentation

- `docs/APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - Double-hashing bug details
- `docs/DER_SIGNATURE_LENGTH_VARIABILITY.md` - Why DER lengths vary
- `docs/KEYSTORE_DEADLOCK_SIGTRAP.md` - Storage deadlock bug

---

**Date:** 2026-01-17  
**Status:** In progress - dual verification to determine correct signing theory
