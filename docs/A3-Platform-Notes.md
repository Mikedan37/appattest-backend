# Platform Notes

This appendix describes platform-specific behavior and limitations.

## Linux Verification Limitations

On Linux, cryptographic verification of App Attest may fail even when all inputs match exactly (signedBytes, signature DER, public key).

This appears to be due to differences between:

- Apple's Secure Enclave / AppleCrypto ECDSA implementation (used on iOS/macOS)
- SwiftCrypto / OpenSSL ECDSA verification on Linux

Apple-generated App Attest signatures are valid and verify correctly on Apple platforms, but cross-platform verification is not guaranteed and is not officially documented or supported by Apple.

### Implications

- Verification failures on Linux do not necessarily indicate malformed signatures or protocol errors
- All byte-level fingerprints can match while verification still fails
- This project treats Linux verification as best-effort

### Platform Considerations

For systems requiring verification, consider:

- Running verification on macOS or Apple Silicon
- Using Apple-supported infrastructure

Linux support is retained for research, inspection, and protocol-level validation.

## High-S / Low-S Signature Normalization

ECDSA signatures have signature malleability: for any valid signature `(r, s)`, the signature `(r, n - s)` is also valid (where `n` is the curve order).

Some cryptographic implementations (including CryptoKit/SwiftCrypto on Linux) reject "high-S" signatures (where `s > n/2`) to prevent signature malleability attacks.

**Symptoms:**
- All cryptographic inputs match byte-for-byte (authenticatorData, clientDataHash, signedBytes, nonce, publicKey)
- Both SwiftCrypto and OpenSSL verification fail with `ECDSA_VERIFY_FAILED`
- Signature DER parses correctly
- No other errors in logs

**Root Cause:**
Apple devices may generate signatures with `s > n/2` (high-S). The backend's strict verification may reject these signatures even though they are cryptographically valid.

**Solution:**
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
