# Logging

This chapter describes the logging format and forensic analysis capabilities.

## Structured Trace Blocks

The service logs structured trace blocks for forensic analysis:

- `[KEY_REGISTERED]` - Public key fingerprint at registration
- `[CLIENT_DATA_HASH]` - Challenge generation and storage
- `[VERIFY_TRACE][TRANSPORT]` - Assertion object integrity
- `[VERIFY_TRACE][CLIENT_DATA_HASH]` - Stored challenge integrity
- `[VERIFY_TRACE][KEY_IDENTITY]` - Public key identity and lineage
- `[VERIFY_TRACE][DECODED]` - Decoded authenticatorData and signature
- `[VERIFY_TRACE][DIGESTS]` - Dual verification attempts
- `[SIX_VALUES]` - Six-value block matching frontend format

## SIX_VALUES Logging

Every verify request logs a `SIX_VALUES` block (even on early returns after assertion decode). This appears in `journalctl`:

```bash
sudo journalctl -u appattest-backend | grep SIX_VALUES
```

Example output:
```
SIX_VALUES_BEGIN verifyRunID=<uuid>
SIX_VALUES authenticatorData.sha256=<hex>
SIX_VALUES clientDataHash.sha256=<hex>
SIX_VALUES signedBytes.sha256=<hex>
SIX_VALUES signature.sha256=<hex>
SIX_VALUES keyID_sha256=<hex>
SIX_VALUES publicKeyX963.sha256=<hex>
SIX_VALUES_END verifyRunID=<uuid>
```

Compare these values with iOS logs to identify mismatches.

## VERIFY_TRACE Stages

The verification trace follows this order:

1. **TRANSPORT** - Assertion object integrity
   - Logs: `assertionObject.sha256`

2. **CLIENT_DATA_HASH** - Stored challenge integrity
   - Logs: `clientDataHash.sha256`

3. **KEY_IDENTITY** - Public key identity
   - Logs: `publicKeyX963.sha256`, `hex_prefix20`, `hex_suffix20`, `base64`

4. **DECODED** - Decoded assertion components
   - Logs: `authenticatorData.sha256`, `signatureDER.sha256`

5. **DIGESTS** - Dual verification attempts
   - Logs: `attemptA_signedBytes.sha256`, `attemptB_signedBytes.sha256`

6. **RESULT** - Final verification outcome
   - Logs: verification result and reason

## Forensic Analysis

Use the forensics output to compare byte-for-byte:

1. **authenticatorData.sha256** - Must match iOS `authenticatorData.sha256`
2. **clientDataHash.sha256** - Must match iOS `clientDataHash.sha256`
3. **signedBytesA.sha256** or **signedBytesB.sha256** - One must match iOS `signedBytes.sha256`
4. **signature.sha256** - Must match iOS `signature.sha256`
5. **publicKeyX963.sha256** - Must match the key registered for this `keyID`

If all hashes match but verification fails, the issue is in digest construction or verification mode (should be DIGEST_ONLY).

## Cryptographic Logging Notes

This service may emit full hex dumps of cryptographic artifacts (public keys, signatures, authenticatorData) for forensic analysis.

These logs:
- Do NOT contain private keys
- May include ephemeral per-request material
- Are intended for development and forensic debugging

Debug and forensic logging is controlled via environment variables (e.g. `APP_ATTEST_DEBUG_*`) and SHOULD NOT be enabled in production without appropriate access controls.

## Debug Forensics

When verification fails, you can enable detailed forensic output to diagnose byte-level mismatches. This is DEV-ONLY and must not be enabled in production.

### Enable Forensics

Set environment variable `APP_ATTEST_DEBUG_FORENSICS`:

- `APP_ATTEST_DEBUG_FORENSICS=1` - Include forensics in failure responses only
- `APP_ATTEST_DEBUG_FORENSICS=2` - Include forensics in all responses (success and failure)

When enabled, failed verification responses include a `forensics` object with byte-level details including hex dumps, lengths, and SHA256 hashes of all intermediate values.
