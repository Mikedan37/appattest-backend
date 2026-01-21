# Assertion Verification Approach

## Signature Formats

ECDSA signatures can be encoded in two formats:

1. **DER (Distinguished Encoding Rules)**: ASN.1-encoded SEQUENCE { INTEGER r, INTEGER s }
   - Variable length (typically 70-72 bytes for P-256, but can be 71, 73, etc.)
   - Starts with `0x30` (SEQUENCE tag)
   - Used by WebAuthn, App Attest, and most production systems

2. **Raw P1363**: 64-byte concatenation `r || s` (32 bytes each)
   - Fixed length: exactly 64 bytes
   - No ASN.1 structure
   - Used by some crypto libraries and test code

## Verification Modes

CryptoKit's `isValidSignature` has two overloads:

1. **MESSAGE mode**: `isValidSignature(_:for: Data)`
   - CryptoKit hashes the message internally with SHA256
   - Used when the signer also hashed internally

2. **DIGEST mode**: `isValidSignature(_:for: SHA256.Digest)`
   - CryptoKit uses the digest directly (no hashing)
   - Used when the signer signed a pre-computed digest

## Dual Verification Approach

The verifier performs two verification attempts using DIGEST mode:

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

Verification succeeds if either attempt succeeds.

DIGEST mode is used to make the exact digest being verified explicit. If both attempts fail, the issue is identity mismatch (wrong key/clientDataHash/bytes), not hashing semantics.

## Canonical Verification Function

All App Attest verification uses:

```swift
func verifyAssertion(
    publicKeyX963: Data,
    authenticatorData: Data,
    clientDataHash: Data,
    signatureDER: Data,
    logger: Logger
) throws -> Bool
```

## Requirements

1. **Signature format**: If signature starts with `0x30`, it uses `derRepresentation` initializer
2. **Public key format**: `P256.Signing.PublicKey(x963Representation:)` (65 bytes, `0x04` prefix)
3. **Dual verification**: Both signing theories are tested using DIGEST mode
4. **Signature format validation**: If signature starts with `0x30` but doesn't parse as DER, verification fails
5. **DER only**: No "try both DER and raw" fallbacks - DER is required

## Regression Prevention

1. **Single canonical function**: All verification goes through one function
2. **Compile-time and runtime checks**: Prevent wrong API usage
3. **Explicit logging**: `VERIFICATION_DUAL_ATTEMPT` block shows both attempts with all intermediate values
4. **No fallbacks**: If DER parsing fails, verification fails - no silent fallback to raw

## Code Location

- **Canonical verifier**: `Sources/AppAttestBackend/Crypto/AppAttestAssertionVerifier.swift`
- **Route handler**: `Sources/AppAttestBackend/main.swift` (calls `verifyAssertion()` only)

## Related Documentation

- `docs/APP_ATTEST_CRYPTOKIT_DOUBLE_HASH_GOTCHA.md` - MESSAGE vs DIGEST mode details
- `docs/DER_SIGNATURE_LENGTH_VARIABILITY.md` - DER length variability
- `docs/KEYSTORE_DEADLOCK_SIGTRAP.md` - Storage concurrency safety
