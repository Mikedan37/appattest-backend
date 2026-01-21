# Signature Format Detection Rules

## Overview

App Attest assertion signatures can be encoded in two formats:
1. **DER (ASN.1)**: Variable length, typically 70-72 bytes for P-256
2. **RAW P1363**: Exactly 64 bytes (r||s, 32 bytes each)

This document describes the robust detection rules used in the backend verification code.

## Detection Rules (CRITICAL)

### Rule 1: Length-Based Detection (Primary)

**If `signature.count == 64`:**
- Treat as **RAW P1363** format
- Parse using `P256.Signing.ECDSASignature(rawRepresentation:)`
- Verification method: `RAW_64`

**Rationale:** This is the only unambiguous way to detect RAW format. A 64-byte signature is always RAW P1363 (r||s concatenation).

### Rule 2: DER Parse Attempt (Fallback)

**If `signature.count != 64`:**
- Attempt DER parse using `P256.Signing.ECDSASignature(derRepresentation:)`
- If parse succeeds: Verification method: `DER_PARSED`
- If parse fails: Reject with `invalid_signature_encoding`

**Rationale:** DER-encoded signatures are variable length (typically 70-72 bytes for P-256). If it's not 64 bytes and not valid DER, it's invalid.

### Rule 3: Verification Result

**After successful parse:**
- Verify using MESSAGE mode: `publicKey.isValidSignature(signature, for: message)`
- If verification fails, this indicates a genuine signature mismatch (wrong key, wrong message, or corrupted signature)
- There is no fallback - the signature simply doesn't verify

## Forbidden Heuristics

### ❌ NEVER: "First byte == 0x30 means DER"

**Why this is unsafe:**
- A RAW P1363 signature can start with `0x30` by coincidence
- The `r` component of an ECDSA signature is a random 32-byte integer
- Approximately 1/256 of all RAW signatures will start with `0x30`
- Using this heuristic would incorrectly parse ~0.4% of RAW signatures as DER

**Example of failure:**
```
RAW signature: 30a1b2c3... (64 bytes total)
First byte: 0x30
Heuristic says: "DER"
Actual: RAW P1363
Result: Parse error or incorrect verification
```

## Verification Mode

All signature verification uses **MESSAGE mode**:
```swift
publicKey.isValidSignature(signature, for: message)
```

Where `message = authenticatorData || clientDataHash` (raw bytes concatenation).

**Why MESSAGE mode:**
- CryptoKit hashes the message internally with SHA-256
- This matches App Attest's signing behavior: `ECDSA over SHA-256(authenticatorData || clientDataHash)`
- We do NOT pre-hash the message (that would cause double-hashing)

## Logging

The verification code logs:
- `signature_length`: Exact byte length
- `signature_firstByte`: First byte in hex (for forensic analysis)
- `signature_hex_prefix`: First 16 bytes in hex
- `signature_sha256`: SHA-256 of raw signature bytes
- `signature_encoding`: `RAW_P1363` or `DER`
- `ecdsa_parse`: `success` or `failure`
- `verification_method`: `RAW_64` or `DER_PARSED`
- `verification_result`: `accepted` or `rejected`

## Implementation Location

The signature format detection logic is in:
- `Sources/AppAttestBackend/main.swift`
- Function: `verifyAssertion(publicKeyX963:signatureDER:message:logger:)`
- Lines: ~983-1089

## Testing

Unit tests should verify:
1. 64-byte signatures are parsed as RAW P1363
2. DER signatures (70-72 bytes) are parsed as DER
3. Invalid signatures (wrong length, invalid DER) are rejected
4. The defensive fallback path is exercised when DER parse succeeds but verification fails

## References

- [P1363 Format](https://standards.ieee.org/standard/1363-2000.html): IEEE Standard Specifications for Public-Key Cryptography
- [DER Encoding](https://www.itu.int/rec/T-REC-X.690/): ASN.1 encoding rules
- [CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit): Apple's cryptographic framework
