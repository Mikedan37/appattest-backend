# Verification Self-Audit Report

## Purpose

This document records the forensic analysis of App Attest assertion verification failures, including OpenSSL cross-checks and exact byte-level comparisons.

## Forensic Dump Location

All verification artifacts are dumped to `/tmp/appattest/` for each verify attempt:
- `{prefix}_assertion.cbor` - Raw assertionObject bytes
- `{prefix}_pubkey.x963` - Public key in X9.63 format (65 bytes)
- `{prefix}_pubkey.pem` - Public key in PEM format (for OpenSSL)
- `{prefix}_signature.der` - ASN.1 DER signature bytes
- `{prefix}_message.bin` - Exact message bytes verified (authenticatorData || clientDataHash)
- `{prefix}_meta.txt` - Metadata with SHA256 hashes and lengths

Prefix is first 8 hex chars of keyID_sha256.

## OpenSSL Verification Command

For each verify attempt, OpenSSL verification is performed:

```bash
openssl dgst -sha256 -verify /tmp/appattest/{prefix}_pubkey.pem \
  -signature /tmp/appattest/{prefix}_signature.der \
  /tmp/appattest/{prefix}_message.bin
```

## Interpretation Guide

### OpenSSL Verifies, swift-crypto Rejects

**Root Cause:** API misuse or signature object construction issue

**Check:**
1. Signature object construction:
   - If signature is DER (starts with 0x30): `ECDSASignature(derRepresentation:)`
   - If signature is 64 bytes: `ECDSASignature(rawRepresentation:)`
2. Overload usage:
   - Using `isValidSignature(_:for: Data)` with message bytes (correct)
   - NOT using `isValidSignature(_:for: Digest)` with pre-hashed digest (wrong)
3. Double-hashing:
   - Message is NOT pre-hashed before passing to message-based verify
   - Digest is NOT passed to message-based verify

### Both Reject

**Root Cause:** Bytes/key mismatch (extraction issue)

**Check:**
1. Message bytes:
   - `message.bin` SHA256 matches expected `authenticatorData || clientDataHash`
   - No mutations, no encoding, no extra bytes
2. Public key extraction:
   - `pubkey.x963` is 65 bytes, starts with 0x04
   - Extracted from COSE key (-2 = x, -3 = y) correctly
   - Matches the key that signed the assertion
3. Signature extraction:
   - `signature.der` is valid ASN.1 DER
   - Extracted from correct CBOR field (integer key 2 or text "signature")
4. AuthenticatorData extraction:
   - Extracted from correct CBOR field (integer key 1 or text "authenticatorData")
   - Length matches expected (typically 37 bytes)

### Both Verify

**Root Cause:** Bug is elsewhere (response handling, wrong branch, etc.)

**Check:**
1. Response construction
2. Error handling paths
3. Logging vs actual return values

## Self-Audit Checklist

- [ ] Message bytes (`message.bin`) SHA256 matches expected
- [ ] Public key (`pubkey.x963`) is 65 bytes, starts with 0x04
- [ ] Public key SHA256 matches registration log
- [ ] Signature (`signature.der`) is valid DER (starts with 0x30)
- [ ] OpenSSL verification result matches swift-crypto result
- [ ] If mismatch: signature object construction and overload usage checked

## Example Audit

```
keyID_sha256: 4e6435b72b14b244349d059fd1be9e03ed40081b39933b5385845bf591595ea8
pubkey_sha256: 944d5e855baf659a0c518fb2a15740ebf03ae7ae14885b89ff261d2c1fb55e59
message_sha256: 305f6bb2596c56def116e643e302bff2b24a06d8ec75c402291f8e12d1bd6510
signatureDER_sha256: b4e9264a0721d6c4b5cac348cd3d07cc9db55f2d18e316e27dacfb5863950003

OpenSSL: Verified OK
swift-crypto: rejected

Conclusion: API misuse - signature object construction or overload issue
```
