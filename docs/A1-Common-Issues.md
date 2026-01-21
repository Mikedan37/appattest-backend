# Common Issues

This appendix describes common issues and troubleshooting approaches.

## DER vs Raw Signature Format

ECDSA signatures can be encoded in two formats:

1. **DER (Distinguished Encoding Rules)**: ASN.1-encoded `SEQUENCE { INTEGER r, INTEGER s }`
   - Variable length (typically 70-72 bytes for P-256, but can be 71, 73, etc.)
   - Starts with `0x30` (SEQUENCE tag)
   - Used by WebAuthn, App Attest, and most production systems

2. **Raw P1363**: 64-byte concatenation `r || s` (32 bytes each)
   - Fixed length: exactly 64 bytes
   - No ASN.1 structure
   - Used by some crypto libraries and test code

**Fix:** If signature starts with `0x30`, it MUST be DER. Use `P256.Signing.ECDSASignature(derRepresentation:)` initializer.

## MESSAGE vs DIGEST Mode

CryptoKit's `isValidSignature` has two overloads:

1. **MESSAGE mode**: `isValidSignature(_:for: Data)`
   - CryptoKit hashes the message internally with SHA256
   - Use when the signer also hashed internally (App Attest)

2. **DIGEST mode**: `isValidSignature(_:for: SHA256.Digest)`
   - CryptoKit uses the digest directly (no hashing)
   - Use when the signer signed a pre-computed digest

**Fix:** Use DIGEST mode for App Attest verification. Pass a `SHA256.Digest` type, not raw `Data`.

## Identity Mismatches Masquerading as Crypto Failures

When verification fails, it may not be a cryptographic issue. Common causes:

- Wrong public key (wrong cert, wrong representation, wrong parsing offset)
- Wrong challenge (different challenge, expired, consumed)
- Wrong bytes (CBOR decoding error, byte truncation, encoding mismatch)

**Fix:** Use dual DIGEST-mode attempts to prove which signing theory is correct. If both fail, it's an identity mismatch, not a hashing issue.

## All Fingerprints Match But Verify Fails

**Cause:** Public key extraction/storage bug OR signature API misuse OR wrong signing theory

**Symptoms:** Bytes are correct but signature doesn't verify

**Fix:**
- Check public key format (X9.63, 65 bytes, 0x04 prefix)
- Check signature DER encoding (starts with 0x30, valid ASN.1)
- Verify API usage: DIGEST mode (`for: SHA256.Digest`), not MESSAGE mode
- Check which dual attempt succeeded (A or B) to determine correct signing theory

**Diagnostic:** Dump public key, signature, and signedBytes to files, verify with OpenSSL

## Binding Violations

**Cause:** flowID mismatch, keyID mismatch, or verifyRunID mismatch

**Symptoms:** Rejection with explicit binding violation reason

**Fix:**
- Ensure frontend reuses the same `flowID` from REGISTER response
- Ensure frontend sends the same `verifyRunID` (if provided) to CLIENT_DATA_HASH and VERIFY
- Check backend storage key construction (must use canonical format)

**Diagnostic:** Log all binding values at each endpoint, compare
