# DER ECDSA Signature Variable Length: Why Fixed-Size Assumptions Fail

## The Bug

One of the most common cryptography bugs in production App Attest implementations is assuming DER-encoded ECDSA signatures have a fixed length (typically 70 or 72 bytes for P-256).

**This assumption is incorrect.** DER signatures are **variable-length** by design.

## Why DER Signatures Are Variable Length

ASN.1 DER encoding of ECDSA signatures follows this structure:

```
SEQUENCE {
    INTEGER r,  -- Variable length (32 bytes + padding)
    INTEGER s   -- Variable length (32 bytes + padding)
}
```

### INTEGER Encoding Rules

1. **Leading zero padding**: If the high bit of the first byte is set, a leading zero byte is prepended to ensure the INTEGER is encoded as positive (two's complement rule).
2. **Variable-length encoding**: The length depends on the actual value of r and s.

### Example Lengths for P-256 ECDSA

For P-256 ECDSA, r and s are each 32 bytes, but DER encoding can produce:

- **70 bytes**: Minimal encoding (no padding needed for either r or s)
- **71 bytes**: One INTEGER needs padding (one leading zero byte)
- **72 bytes**: Both INTEGERs need padding (two leading zero bytes)
- **Other lengths**: Possible depending on specific r/s values and encoding quirks

**Real-world example from our logs:**
- iOS emitted a **71-byte DER signature**
- It parsed cleanly as valid DER
- But code assuming "DER == 70 or 72 bytes" would reject it

## Why This Bug Is Common

### 1. Apple Frameworks Hide Complexity

Apple's `SecKeyVerifySignature` and `CryptoKit` handle DER parsing internally. Most iOS developers never see the raw DER bytes, so they don't realize DER is variable-length.

### 2. Backend Engineers Rarely Parse ASN.1

Most backend engineers:
- Never parse ASN.1 DER manually
- Rely on cryptographic libraries (which handle it correctly)
- See "typical" lengths in documentation (70-72 bytes)
- Incorrectly treat "typical" as "only valid"

### 3. Documentation Ambiguity

Many references show "typical" or "common" lengths without emphasizing that DER is **variable-length by design**. This leads to:

```swift
// ❌ WRONG: Fixed-length assumption
if signature.count == 70 || signature.count == 72 {
    // Treat as DER
}

// ✅ CORRECT: Structure-based detection
if signature.first == 0x30 {
    // Try DER parse
    if let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature) {
        // Valid DER
    }
}
```

## How This Implementation Fixes It

### 1. Structure-Based Detection (Not Length-Based)

```swift
// STEP 3: Classify signature encoding
if signature.first == 0x30 {
    // DER encoding (ASN.1 SEQUENCE tag)
    signatureFormat = "DER"
    // Parse to validate structure
    let sigDER = try P256.Signing.ECDSASignature(derRepresentation: signature)
} else if signature.count == 64 {
    // Raw P1363 (r||s, exactly 64 bytes)
    signatureFormat = "RAW_P1363"
} else {
    // Try DER parse anyway (defensive)
    // Reject only if both checks fail
}
```

### 2. Single-Point Classification

Signature format is classified **exactly once** in STEP 3. Later code uses `signatureFormat` variable, not re-classification.

This prevents "classification drift" where:
- STEP 3 correctly identifies DER
- Later code re-checks with different assumptions
- Valid signatures get rejected

### 3. No Re-Encoding

If a signature is already DER, we use it **as-is** (no re-encoding). Re-encoding can introduce subtle bugs and is unnecessary.

### 4. Fail Closed

If classification fails (not 64 bytes AND DER parse fails), we reject with an explicit error message. We do NOT:
- Auto-convert unknown formats
- Accept malformed ASN.1
- Loosen verification rules

## Code Location

- **Classification**: `Sources/AppAttestBackend/main.swift`, STEP 3 (lines ~2075-2155)
- **Usage**: `signatureFormat` variable is used throughout verification
- **Documentation**: This file + inline comments in code

## Testing

Unit tests should verify:
1. 64-byte signatures are classified as RAW_P1363
2. DER signatures of various lengths (70, 71, 72, 73 bytes) are all classified as DER
3. Invalid signatures (wrong length, malformed DER) are rejected
4. Classification happens exactly once (no duplicate checks)

## References

- [ASN.1 DER Encoding Rules](https://www.itu.int/rec/T-REC-X.690/)
- [ECDSA Signature Encoding](https://tools.ietf.org/html/rfc3279#section-2.2.3)
- [CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit)

## Lesson Learned

**Never assume fixed lengths for variable-length encodings.**

DER is variable-length by design. If your code assumes fixed lengths, you will reject valid signatures. Use structure-based detection (first byte == 0x30 AND successful parse), not length-based heuristics.

This bug appears in production systems because:
- It's subtle (works for "typical" cases)
- It's hard to test (requires specific r/s values)
- Documentation is ambiguous
- Most engineers never see the raw bytes

You crossed the system boundary. You saw the raw bytes. You fixed it.

That's systems security work.
