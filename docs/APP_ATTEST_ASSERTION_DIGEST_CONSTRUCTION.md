# App Attest Assertion Verification: Digest Construction Contract

## Summary

This document describes the **digest construction requirements** observed in our App Attest assertion verification flow. These requirements were discovered through end-to-end forensic logging and A/B digest verification.

**Key Finding:** Successful ECDSA verification requires computing the message digest using:

```
messageDigest = SHA256(authenticatorData || SHA256(clientDataHashBytes))
```

Where `clientDataHashBytes` is the 32-byte value used alongside `authenticatorData` in our assertion flow.

Verifying against:

```
SHA256(authenticatorData || clientDataHashBytes)
```

fails deterministically in our end-to-end tests, even when:
- the stored public key is correct (`keyID == SHA256(pubKeyX9.63)`)
- `rpIdHash` is correct
- the signature DER parses cleanly
- verification uses CryptoKit DIGEST mode (no implicit hashing)

---

## Digest Construction Contract

### What App Attest Signs (Observed in Our Flow)

App Attest signs a **SHA256 digest**, not raw message bytes. The digest is constructed as:

```
messageDigest = SHA256(authenticatorData || SHA256(clientDataHashBytes))
```

Then signed with ECDSA P-256:

```
ECDSA_sign(messageDigest, privateKey)
```

### Why clientDataHashBytes Must Be Re-Hashed

In our implementation, the assertion signature validates **only** when the backend:

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

---

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

**Expected result (observed in our tests):**
- `wrongDigest` → verification fails
- `correctDigest` → verification succeeds

---

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

### ❌ Incorrect (Will Always Fail)

```swift
let signedBytes = authenticatorData + clientDataHashBytes
let digest = SHA256.hash(data: signedBytes)
publicKey.isValidSignature(signatureDER, for: digest)
```

---

## Why This Is Easy to Miss

### 1. Naming Trap

`clientDataHash` sounds like a terminal value. In this flow, treating it as terminal breaks verification.

### 2. CryptoKit Overload Trap

Even after switching to DIGEST mode (see `APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md`), the digest inputs can still be semantically wrong.

### 3. Unit Test Trap

If you sign + verify within the same environment, you can unknowingly bake in the wrong construction and still pass.

### 4. Documentation Gap

Apple's public documentation does not explicitly describe this exact construction. Internal implementations use structured APIs that hide this detail.

---

## Security Implications

- This is **not a vulnerability**
- It is a **sharp edge** that can silently break verification
- Incorrect handling leads to **false negatives**, not false positives
- Security is maintained (failures are conservative)

---

## Code Location

**Implementation:** `Sources/AppAttestBackend/main.swift` lines ~2212-2225

**Key Code:**
```swift
// Empirically required for our App Attest assertion verification flow:
let clientDataHashHashed = SHA256.hash(data: clientDataHashData)
let signedBytes = authenticatorData + clientDataHashHashed
let messageDigest = SHA256.hash(data: signedBytes)
```

---

## Related Documentation

- `APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - MESSAGE vs DIGEST mode (CryptoKit API gotcha)
- `DER_SIGNATURE_LENGTH_VARIABILITY.md` - DER signature length variability
- `AppAttest-ClientDataHash.md` - Backend-owned clientDataHash model

---

## Testing

After this fix:
- ✅ Verification succeeds deterministically
- ✅ Diagnostic logs show `old_messageDigest_sha256` (wrong) vs `new_messageDigest_sha256` (correct)
- ✅ Only the correct digest path verifies successfully

---

## Notes

This document describes behavior **observed in our end-to-end App Attest assertion flow** via forensic logs and digest A/B verification. Apple's public docs do not explicitly describe this exact construction.

This is an **empirically required** construction for our implementation. Other implementations may differ, but this is what works in our end-to-end tests.

---

## For Future Contributors

If you see code that constructs `signedBytes` as:

```swift
let signedBytes = authenticatorData + clientDataHashBytes  // ❌ WRONG
```

**STOP.** This is incorrect for our flow. It must be:

```swift
let clientDataHashHashed = SHA256.hash(data: clientDataHashBytes)
let signedBytes = authenticatorData + clientDataHashHashed  // ✅ CORRECT
```

This is not optional. This is what our end-to-end tests require.

---

## Lesson Learned

**Never assume naming implies semantics.**

`clientDataHash` is named like a terminal value, but in our assertion verification flow, it must be re-hashed before concatenation. The Secure Enclave appears to re-hash it internally, and our backend must match that behavior exactly.

This is why forensic logging is essential: it proves all the "obvious" things are correct, leaving only the subtle protocol mismatch.
