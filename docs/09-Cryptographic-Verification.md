# Cryptographic Verification

This chapter describes the cryptographic verification mechanics.

## Signed Bytes Construction

The backend constructs signed bytes as:

```
signedBytes = authenticatorData || clientDataHash
nonce = SHA256(signedBytes)
```

Where:
- `authenticatorData`: Extracted from assertion CBOR map (key 1 or "authenticatorData", bstr)
- `clientDataHash`: 32-byte SHA256 hash stored and supplied by backend
- `||`: Raw byte concatenation (no encoding, no hashing, no COSE structures)

## Verification Process

The backend performs dual DIGEST-mode verification attempts:

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

One of these attempts must succeed for verification to pass. If both fail, it indicates an identity mismatch (wrong key, challenge, or bytes), not a hashing issue.

## Signature Format

- Format: ASN.1 DER-encoded ECDSA signature
- Curve: P-256 (secp256r1)
- Hash: SHA256
- Normalization: High-S signatures are normalized to low-S before verification (if normalization is enabled)

## DIGEST Mode

All signature verification uses DIGEST mode:

```swift
publicKey.isValidSignature(signature, for: digest)
```

Where `digest` is a `SHA256.Digest` type, not raw `Data`.

**Why DIGEST mode:**
- CryptoKit hashes the message internally with SHA-256
- This matches App Attest's signing behavior: `ECDSA over SHA-256(authenticatorData || clientDataHash)`
- We do NOT pre-hash the message (that would cause double-hashing)

## High-S / Low-S Signature Normalization

ECDSA signatures have signature malleability: for any valid signature `(r, s)`, the signature `(r, n - s)` is also valid (where `n` is the curve order).

Some cryptographic implementations (including CryptoKit/SwiftCrypto on Linux) reject "high-S" signatures (where `s > n/2`) to prevent signature malleability attacks.

The backend normalizes all ECDSA signatures to low-S before verification:

1. Parse DER signature to extract `r` and `s` values
2. Compare `s` with `n/2` (half the curve order)
3. If `s > n/2`: Normalize to `s = n - s`
4. Re-encode to DER with proper INTEGER encoding
5. Verify using normalized signature

**P-256 Curve Order:**
```
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
halfN = n >> 1
```

Normalizing to low-S provides:
- Consistency: All signatures are in canonical form
- Compatibility: Works with strict implementations that reject high-S
- Transparency: Logs clearly indicate when normalization occurred
