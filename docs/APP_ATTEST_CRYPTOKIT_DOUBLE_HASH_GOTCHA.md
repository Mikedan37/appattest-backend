# App Attest CryptoKit Double-Hash Gotcha: MESSAGE vs DIGEST Mode

## Executive Summary

App Attest assertion verification was failing due to **double-hashing** caused by using CryptoKit's MESSAGE mode instead of DIGEST mode. This document explains what happened, why it's common, and how it was fixed.

**⚠️ IMPORTANT:** This document covers the MESSAGE vs DIGEST mode issue. For the separate issue of `clientDataHash` being re-hashed, see `APP_ATTEST_ASSERTION_DIGEST_CONSTRUCTION.md`.

---

## What App Attest Signs (Observed in Our Flow)

Apple App Attest signs a **SHA256 digest**, not raw message bytes:

```
ECDSA_sign( SHA256(authenticatorData || SHA256(clientDataHash)) )
```

The Secure Enclave on the device:
1. Constructs the message (see `APP_ATTEST_ASSERTION_DIGEST_CONSTRUCTION.md` for exact construction)
2. Computes `SHA256` of that message
3. Signs the resulting 32-byte digest with ECDSA P-256

**Key Point:** The signature is over a digest, not the raw message.

---

## What CryptoKit MESSAGE Mode Does

CryptoKit provides two overloads for signature verification:

```swift
// MESSAGE mode — CryptoKit hashes internally
func isValidSignature(
    _ signature: P256.Signing.ECDSASignature,
    for data: Data
) -> Bool

// DIGEST mode — You provide the hash
func isValidSignature(
    _ signature: P256.Signing.ECDSASignature,
    for digest: SHA256.Digest
) -> Bool
```

### MESSAGE Mode Behavior

When you pass `Data` to `isValidSignature(_:for:)`:
1. CryptoKit computes `SHA256(data)` internally
2. Verifies the signature against that digest

This is correct for general-purpose signing where you control both sides.

### The Problem

App Attest **already** provides a digest (it signed `SHA256(message)`). If you pass raw `Data` to MESSAGE mode:
1. CryptoKit computes `SHA256(data)` again
2. This results in `SHA256(SHA256(message))`
3. But App Attest signed `SHA256(message)`
4. **Verification fails deterministically**

---

## How Double-Hashing Happens

### The Buggy Code

```swift
// ❌ WRONG: Causes double-hashing
let signedBytes = authenticatorData + SHA256.hash(data: clientDataHashBytes)
let isValid = publicKey.isValidSignature(signature, for: signedBytes)
```

**What happens:**
1. App Attest signed: `ECDSA_sign(SHA256(signedBytes))`
2. Backend verifies: `isValidSignature(signature, for: signedBytes)`
3. CryptoKit internally computes: `SHA256(signedBytes)`
4. CryptoKit verifies: `ECDSA_verify(signature, SHA256(signedBytes))`
5. **Mismatch:** Signature is over `SHA256(signedBytes)`, but CryptoKit is verifying `SHA256(SHA256(signedBytes))`

### The Correct Code

```swift
// ✅ CORRECT: No double-hashing
let signedBytes = authenticatorData + SHA256.hash(data: clientDataHashBytes)
let messageDigest = SHA256.hash(data: signedBytes)
let isValid = publicKey.isValidSignature(signature, for: messageDigest)
```

**What happens:**
1. App Attest signed: `ECDSA_sign(SHA256(signedBytes))`
2. Backend computes: `messageDigest = SHA256(signedBytes)`
3. Backend verifies: `isValidSignature(signature, for: messageDigest)`
4. CryptoKit verifies: `ECDSA_verify(signature, messageDigest)`
5. **Match:** Signature is over `SHA256(signedBytes)`, CryptoKit verifies against `SHA256(signedBytes)`

---

## Why Everything Looked Correct But Failed

### Forensic Logs Showed Correctness

All forensic logging confirmed:
- ✅ Correct public key (65 bytes, 0x04 prefix)
- ✅ Correct signature format (DER, variable-length)
- ✅ Correct `signedBytes` construction
- ✅ Byte-for-byte integrity across frontend and backend
- ✅ Correct signature parsing (r and s extracted correctly)

**But verification still failed** because of the double-hashing mismatch.

### Why This Is Hard to Debug

1. **No obvious error:** CryptoKit doesn't throw an error, it just returns `false`
2. **Logs look correct:** All hashes and bytes match expectations
3. **API ambiguity:** The `Data` overload looks like it should work
4. **Documentation gap:** Apple doesn't explicitly state "App Attest signs a digest"

---

## The Correct Fix (DIGEST Mode)

### Implementation

```swift
// Construct signedBytes (see APP_ATTEST_ASSERTION_DIGEST_CONSTRUCTION.md)
let clientDataHashHashed = SHA256.hash(data: clientDataHashBytes)
let signedBytes = authenticatorData + clientDataHashHashed

// IMPORTANT:
// App Attest signs SHA256(signedBytes).
// CryptoKit hashes raw messages automatically when verifying Data,
// so we MUST pass a Digest here to avoid double-hashing.
let messageDigest = SHA256.hash(data: signedBytes)

// Verify using DIGEST mode (not MESSAGE mode)
let isValid = publicKey.isValidSignature(signatureDER, for: messageDigest)
```

### Key Changes

1. **Explicit digest computation:** `let messageDigest = SHA256.hash(data: signedBytes)`
2. **DIGEST mode verification:** `isValidSignature(signature, for: messageDigest)`
3. **Never pass raw `Data`:** All verification uses `SHA256.Digest`

---

## Why This Bug Is Common

### 1. API Overload Ambiguity

CryptoKit's API design makes it easy to use the wrong overload:

```swift
// These look similar but behave differently
isValidSignature(signature, for: data)      // MESSAGE mode
isValidSignature(signature, for: digest)    // DIGEST mode
```

Most developers assume MESSAGE mode is correct because:
- It's more convenient (no need to hash manually)
- It's the more common pattern in general-purpose crypto
- The API doesn't warn you about the difference

### 2. Misleading Unit Tests

Unit tests often pass because they use MESSAGE mode consistently:

```swift
// Test code (works in tests, wrong for App Attest)
let message = "test message"
let signature = privateKey.signature(for: message)!
let isValid = publicKey.isValidSignature(signature, for: message) // ✅ Works
```

This works because you control both signing and verification. But App Attest uses DIGEST mode on the device.

### 3. Undocumented App Attest Behavior

Apple's App Attest documentation doesn't explicitly state:
- "App Attest signs a SHA256 digest"
- "Use DIGEST mode, not MESSAGE mode"
- "Passing raw Data causes double-hashing"

Most developers discover this through trial and error (or forensic debugging).

### 4. Silent Failure

CryptoKit doesn't throw an error for double-hashing. It just returns `false`, making it hard to distinguish from:
- Wrong public key
- Corrupted signature
- Message mismatch
- Other verification failures

---

## Verification Mode Comparison

| Mode | What You Pass | What CryptoKit Does | Use Case |
|------|---------------|---------------------|----------|
| **MESSAGE** | `Data` (raw bytes) | Hashes internally with SHA256 | General-purpose signing where you control both sides |
| **DIGEST** | `SHA256.Digest` | Uses digest directly | App Attest, WebAuthn, other protocols that sign digests |

---

## Code Locations

### Fixed Verification Paths

1. **STEP 4 Dual Verification**: `Sources/AppAttestBackend/main.swift` lines ~2212-2252
   - DER verification: `isValidSignature(sigDER, for: messageDigest)`
   - RAW verification: `isValidSignature(sigRaw, for: messageDigest)`

2. **Legacy verifyAssertion**: `Sources/AppAttestBackend/main.swift` lines ~1010-1053
   - RAW path: `isValidSignature(signature, for: messageDigest)`
   - DER path: `isValidSignature(signature, for: messageDigest)`

### No MESSAGE Mode Remaining

All App Attest verification paths now use DIGEST mode. Any future code that uses MESSAGE mode (`for: Data`) in the App Attest path is a bug.

---

## Testing

After this fix:
- ✅ DER signatures verify successfully
- ✅ RAW signatures verify successfully
- ✅ No invariant checks change
- ✅ Forensic hashes remain correct
- ✅ Verification succeeds deterministically

### Regression Test

To verify the fix is working:

1. Check logs for `verification_mode: DIGEST`
2. Verify `messageDigest_sha256 == SHA256(signedBytes_sha256)`
3. Confirm `verification_der: true` or `verification_raw: true`
4. Assert no MESSAGE mode calls remain in App Attest paths

---

## References

- [CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit)
- [App Attest Documentation](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/) (similar digest-signing pattern)

---

## Lesson Learned

**When verifying signatures from external systems, check what they actually sign.**

App Attest signs a digest. CryptoKit's MESSAGE mode assumes you're signing raw bytes. This mismatch causes silent verification failures.

The fix is simple: use DIGEST mode. But finding it requires understanding both what App Attest does and what CryptoKit expects.

This is why forensic logging is essential: it proves all the "obvious" things are correct, leaving only the subtle API mismatch.

---

## Why Almost Nobody Ships End-to-End App Attest

This bug is one of many reasons why most teams don't build complete App Attest verifiers:

1. **Undocumented behavior:** Apple doesn't explicitly state App Attest signs digests
2. **API ambiguity:** CryptoKit's overloads make it easy to use the wrong one
3. **Silent failures:** No clear error message for double-hashing
4. **Forensic debugging required:** You need byte-level logging to find it
5. **Protocol complexity:** Multiple failure modes look identical

You didn't miss something obvious. You found the thing everyone else steps around and pretends doesn't exist.

**Hate it. Respect it. Ship it.**
