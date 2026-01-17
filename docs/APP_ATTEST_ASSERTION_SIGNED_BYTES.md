# App Attest Assertion Signed Bytes

## Key Point: App Attest Assertion Uses COSE Sig_structure

App Attest assertions are **CBOR maps**, not COSE_Sign1 structures.

**Assertion format:**
- First byte: `0xa2` (CBOR map with 2 pairs)
- Structure: `{ "authenticatorData": <bytes>, "signature": <bytes> }`
- This is a simple CBOR map, not a COSE_Sign1 array

## Signed Bytes

The signature is computed over a **COSE Sig_structure** (CBOR array):

```
Sig_structure = [
  "Signature1",                    // text string (item 0)
  protected_headers,              // bstr (empty for App Attest) (item 1)
  external_aad,                   // bstr (empty for App Attest) (item 2)
  authenticatorData || clientDataHash  // bstr (item 3)
]
```

The signature is over:
```
SHA256(CBOR.encode(Sig_structure))
```

**NOT** over raw concatenation:
```
SHA256(authenticatorData || clientDataHash)  // ❌ WRONG
```

## Common Misconception (CORRECTED)

**Previous incorrect assumption:**
- Earlier documentation stated signed bytes were raw concatenation
- This was **incorrect** - Apple signs over COSE Sig_structure

**Correct implementation:**
- Construct COSE Sig_structure: `["Signature1", {}, {}, authenticatorData || clientDataHash]`
- CBOR-encode the Sig_structure array
- Verify over the CBOR-encoded Sig_structure bytes
- swift-crypto's `isValidSignature(_:for: Data)` hashes the Data parameter internally

**Do:**
- Construct Sig_structure as CBOR array
- Pass CBOR-encoded Sig_structure bytes to verifier
- Let the crypto library hash internally

**Do NOT:**
- Verify over raw concatenation (will fail)
- Pre-hash the Sig_structure (crypto library does this)

## Verification API

**Platform:** Linux (swift-crypto)

**API:** `P256.Signing.PublicKey.isValidSignature(_:for: Data)`

**Behavior:**
- Takes `Data` (message bytes)
- Hashes internally using SHA256
- Verifies ECDSA signature over the hash

**Do NOT:**
- Pre-hash the message (would cause double-hashing)
- Pass a Digest object (wrong overload)

## Why This Matters

If you verify over raw concatenation when Apple signed over Sig_structure:
- All components are correct (key, signature, payload)
- But verification fails because you're verifying the wrong bytes
- This is a silent failure that's hard to diagnose

## Reference

- App Attest assertions are CBOR maps, not COSE_Sign1
- Signed bytes = COSE Sig_structure: `["Signature1", {}, {}, authenticatorData || clientDataHash]` (CBOR-encoded)
- The signature is over `SHA256(CBOR.encode(Sig_structure))`, not `SHA256(authenticatorData || clientDataHash)`
- See `docs/COSE_SIG_STRUCTURE_FIX.md` for the full fix documentation
