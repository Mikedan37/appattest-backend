# Signature Format

This appendix describes DER signature format handling.

## DER Encoding

ECDSA signatures are encoded as ASN.1 DER:

```
SEQUENCE {
    INTEGER r,
    INTEGER s
}
```

- Starts with `0x30` (SEQUENCE tag)
- Variable length (typically 70-72 bytes for P-256, but can be 71, 73, etc.)
- Length depends on INTEGER padding, not just signature values

## INTEGER Padding Rules

ASN.1 INTEGER encoding requires:

- Leading zero bytes are removed (unless the first byte would be >= 0x80, in which case a zero byte is prepended)
- This causes variable-length signatures even for the same curve

**Example:**
- If `r` or `s` starts with a byte >= 0x80, a zero byte is prepended
- This increases the signature length by 1 byte
- If both `r` and `s` need padding, length increases by 2 bytes

## Signature Format Detection

The backend detects signature format by first byte:

- `0x30` → DER format
- Otherwise → Invalid or raw format (not supported)

**Rule:** If signature starts with `0x30`, it MUST be DER. No exceptions.

## Parsing

```swift
guard signatureDER.first == 0x30 else {
    throw AppAttestVerificationError.invalidSignatureFormat
}
let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
```

## Variable Length

DER signatures are variable length because:

1. INTEGER values may or may not need leading zero padding
2. SEQUENCE length encoding depends on total content length
3. This is normal and expected behavior

Do not assume fixed-length signatures. Always parse DER format.
