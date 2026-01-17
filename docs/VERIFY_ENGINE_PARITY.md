# Verification Engine Parity: swift-crypto vs CryptoKit

## Platform Differences

**Backend Platform:** Linux (swift-crypto)
**iOS Platform:** macOS/iOS (CryptoKit)

Both use the same API name `isValidSignature(_:for: Data)`, but implementation details may differ.

## API Semantics

### swift-crypto (Linux)

```swift
public func isValidSignature<D: DataProtocol>(
    _ signature: P256.Signing.ECDSASignature,
    for data: D
) -> Bool {
    return self.isValidSignature(signature, for: SHA256.hash(data: data))
}
```

**Behavior:**
- Takes `Data` (message bytes)
- Hashes internally using SHA256
- Calls digest-based verification with the hash

**Do NOT:**
- Pre-hash the message (would cause double-hashing)
- Pass a Digest object (wrong overload - use the Data overload)

### CryptoKit (Apple Platforms)

Same semantics; differences are usually in:
- Parsing strictness (DER encoding acceptance)
- Edge case handling
- Accepted encodings

## Common Pitfalls

### 1. Signature Format

**swift-crypto:**
- `ECDSASignature(derRepresentation:)` - parses ASN.1 DER
- `ECDSASignature(rawRepresentation:)` - parses raw r||s (64 bytes)

**Both platforms:**
- Verification requires an `ECDSASignature` object
- Build it from DER if the signature is DER: `ECDSASignature(derRepresentation:)`
- Build it from raw if it's 64-byte r||s: `ECDSASignature(rawRepresentation:)`
- You can use either format - no need to convert raw to DER for swift-crypto/CryptoKit
- Example with raw signature:
  ```swift
  let sig = try P256.Signing.ECDSASignature(rawRepresentation: raw64Bytes)
  let ok = publicKey.isValidSignature(sig, for: message)
  ```

### 2. Public Key Format

**Both platforms:**
- Expect X9.63 uncompressed format: `0x04 || X[32] || Y[32]` (65 bytes)
- Created using `P256.Signing.PublicKey(x963Representation:)`

**Do NOT:**
- Use SPKI/DER format directly
- Use compressed EC point format

### 3. Message Hashing

**Critical:** Pick exactly one overload - do NOT mix them:

**Option 1: Message-based (hashes internally)**
```swift
let message = authenticatorData + clientDataHash
let isValid = publicKey.isValidSignature(signature, for: message)
// Crypto library hashes message internally using SHA256
```

**Option 2: Digest-based (you hash it)**
```swift
let message = authenticatorData + clientDataHash
let digest = SHA256.hash(data: message)
let isValid = publicKey.isValidSignature(signature, for: digest)
// You provide the SHA256 digest, library does NOT hash again
```

**Do NOT:**
- Pre-hash and then use message overload (double-hashing)
- Use message bytes with digest overload (wrong type)
- Mix the two approaches

## Verification Cross-Check

To diagnose platform-specific issues:

1. **Add OpenSSL verification** (independent engine)
2. **Compare results:**
   - If OpenSSL = true, swift-crypto = false → API misuse or signature object construction issue
   - If OpenSSL = false, swift-crypto = false → Bytes/key mismatch (extraction issue)
   - If OpenSSL = true, swift-crypto = true → Bug is elsewhere (response handling, etc.)

## Debugging Checklist

- [ ] Signature parses as DER successfully
- [ ] Public key is 65 bytes, starts with 0x04
- [ ] Signed bytes = authenticatorData || clientDataHash (raw concatenation)
- [ ] Using `isValidSignature(_:for: Data)` not digest overload
- [ ] Not pre-hashing the message
- [ ] OpenSSL cross-check agrees with swift-crypto (if implemented)

## References

- swift-crypto source: `Sources/Crypto/Signatures/ECDSA.swift`
- Line 203: `isValidSignature(_:for: Data)` implementation
- Confirms internal SHA256 hashing
