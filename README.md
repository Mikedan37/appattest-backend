# App Attest Backend Verification Service

A backend service that verifies Apple App Attest assertion signatures.

This service implements a reproducible cryptographic verification artifact with explicit authority boundaries.

## Scope

This service performs cryptographic verification only. It does not implement:
- Trust decisions
- Authorization
- Freshness validation
- Replay protection
- Policy logic

A `verified` response indicates that the signature is cryptographically valid for the observed byte sequence. It does not indicate authorization, trust, or freshness.

## Backend Authority

The backend is the sole authority for:

1. **clientDataHash generation**: The backend generates, stores, and supplies `clientDataHash` to the frontend. The frontend does not generate or modify it.

2. **flowID lifecycle**: The backend issues `flowID` during registration and enforces its binding to `keyID` and `clientDataHash` throughout the flow.

3. **Identity bindings**: The backend enforces four mandatory bindings before verification:
   - `flowID ↔ keyID`
   - `flowID ↔ clientDataHash`
   - `keyID ↔ publicKeyX963`
   - `flowID ↔ verifyRunID` (if provided)

All client-provided values (`keyID`, `flowID`, `assertionObject`, `verifyRunID`) are treated as untrusted inputs and validated against stored server state.

## Assertion verification modes

Select via **`APP_ATTEST_ASSERTION_MODE`**: `strict`|`s` ⇒ STRICT; `opaque`|`o` ⇒ OPAQUE. Default: **STRICT**.

| Mode | ECDSA gate | When to use |
|------|------------|-------------|
| **STRICT** | `nonce = SHA256(authenticatorData \|\| clientDataHash)`; reject if `isValidSignature(sig, for: nonce)` is false | Production when CryptoKit verification works on your stack |
| **OPAQUE** | ECDSA is logged only; accept when policy checks pass (keyID, flowID, clientDataHash, signCount monotonic, rpIdHash, structural sanity) | When STRICT rejects valid assertions and forensic logs show byte-identical inputs (CryptoKit/App Attest quirks on some platforms) |

**Pipeline (both modes):**  
`signedBytes = authenticatorData || clientDataHash`, `nonce = SHA256(signedBytes)`.  
ECDSA: `isValidSignature(sig, for: nonce)` (DIGEST, gate in STRICT); `isValidSignature(sig, for: signedBytes)` (MESSAGE, diagnostic only).  
SignCount must be strictly monotonic per key; `VERIFICATION_CANONICAL` is logged once per `verifyRunID`.

**What is verified:** keyID↔publicKey, flowID binding, clientDataHash (server-issued, single-use, not expired), signCount monotonic, rpIdHash, CBOR/signature structure; in STRICT, ECDSA(nonce).

**What is not verified:** whether the assertion is recent, reused, or authorized.

## Platform Notes: Linux Verification Limitations

This project implements full byte-for-byte App Attest attestation and assertion verification, including:

- Canonical `signedBytes` construction (`authenticatorData || clientDataHash`)
- DER-parsed ECDSA signatures
- Public key extraction from the attestation certificate
- Optional low-S normalization
- Deterministic fingerprint logging for frontend ↔ backend parity

### Linux Limitation

On Linux, cryptographic verification of App Attest **may fail even when all inputs match exactly** (signedBytes, signature DER, public key).

This appears to be due to differences between:

- Apple's Secure Enclave / AppleCrypto ECDSA implementation (used on iOS/macOS)
- SwiftCrypto / OpenSSL ECDSA verification on Linux

Apple-generated App Attest signatures are valid and verify correctly on Apple platforms, but **cross-platform verification is not guaranteed** and is not officially documented or supported by Apple.

### Implications

- Verification failures on Linux do **not** necessarily indicate malformed signatures or protocol errors
- All byte-level fingerprints can match while verification still fails
- This project treats Linux verification as *best-effort*

### Recommended Usage

For production systems requiring authoritative verification:

- Run verification on an Apple platform (macOS / Apple Silicon)
- Or delegate verification to Apple-supported infrastructure

Linux support is retained for research, inspection, and protocol-level validation.

## ECDSA High-S / Low-S Signature Normalization

### The Problem

ECDSA signatures have **signature malleability**: for any valid signature `(r, s)`, the signature `(r, n - s)` is also valid (where `n` is the curve order). This means every message has two valid signatures.

Some cryptographic implementations (including CryptoKit/SwiftCrypto on Linux) reject "high-S" signatures (where `s > n/2`) to prevent signature malleability attacks. This is a security best practice recommended by BIP-62 and adopted by Bitcoin Core.

**Symptoms:**
- All cryptographic inputs match byte-for-byte (authenticatorData, clientDataHash, signedBytes, nonce, publicKey)
- Both SwiftCrypto and OpenSSL verification fail with `ECDSA_VERIFY_FAILED`
- Signature DER parses correctly
- No other errors in logs

**Root Cause:**
Apple devices may generate signatures with `s > n/2` (high-S). The backend's strict verification rejects these signatures even though they are cryptographically valid.

### The Solution

The backend now **normalizes all ECDSA signatures to low-S** before verification:

1. **Parse DER signature** to extract `r` and `s` values
2. **Compare `s` with `n/2`** (half the curve order)
3. **If `s > n/2`**: Normalize to `s = n - s`
4. **Re-encode to DER** with proper INTEGER encoding
5. **Verify using normalized signature**

**P-256 Curve Order:**
```
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
halfN = n >> 1
```

### Implementation

The normalization is implemented in `AssertionVerifier.swift`:

- **Function**: `normalizeECDSASignatureToLowS(signatureDER: Data) -> Data`
- **Applied**: Automatically in STRICT mode before all verification attempts
- **Fallback**: If normalization fails, uses original signature (logs error)

### Logging

The backend logs canonicalization results:

- **High-S detected**: `ECDSA canonicalization: HIGH-S detected, normalized to low-S [original_length: X, normalized_length: Y]`
- **Already low-S**: `ECDSA canonicalization: already low-S [signature_length: X]`

**Debug mode** (`APP_ATTEST_DEBUG_SIGNATURE=1`) logs:
- `r_hex`: Original r value
- `s_original_hex`: Original s value
- `s_normalized_hex`: Normalized s value (if changed)
- `was_high_s`: Boolean indicating if normalization occurred

### Why This Works

Normalizing to low-S ensures:
- **Consistency**: All signatures are in canonical form
- **Compatibility**: Works with strict implementations that reject high-S
- **Security**: Prevents signature malleability without rejecting valid signatures
- **Transparency**: Logs clearly indicate when normalization occurred

### References

- **BIP-62**: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- **RFC 6979**: Deterministic ECDSA (recommends low-S)
- **Bitcoin Core**: Adopted low-S requirement in 2016
- **Apple App Attest**: May generate high-S signatures; backend normalizes them

### Testing

The normalization can be tested using the helper function:

```swift
let result = try testECDSANormalization(signatureDER: signatureDER)
// result.normalized: Normalized DER signature
// result.wasHighS: Whether original was high-S
// result.sNormalized: Normalized s value (for verification)
```

The test helper asserts the invariant: `normalized_s <= halfN`.

## Endpoints

### POST /app-attest/register

Extracts and stores a public key from an App Attest attestation object.

**Request:**
```json
{
  "keyID": "<base64>",
  "attestationObject": "<base64>",
  "challenge_base64": "<base64>"
}
```

**Response:**
```json
{
  "status": "registered" | "rejected",
  "reason": "<optional>",
  "flowID": "<uuid>"
}
```

**Behavior:**
- Validates `keyID == SHA256(publicKeyX963)` (App Attest invariant)
- Validates nonce using `challenge_base64`:
  - `clientDataHash = SHA256(challenge)`
  - `nonce = SHA256(authenticatorData || clientDataHash)`
  - nonce must match certificate extension `1.2.840.113635.100.8.2`
- Generates and returns `flowID` (UUID)
- Stores `(keyID, flowID) → publicKeyX963`

**Idempotency:** Multiple requests with the same `keyID` and `attestationObject` are allowed. Each request generates a new `flowID`.

### POST /app-attest/client-data-hash

Generates and stores a `clientDataHash` bound to `(keyID, flowID)`.

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "verifyRunID": "<optional-uuid>"
}
```

**Response:**
```json
{
  "clientDataHash": "<base64>",
  "expiresAt": "<ISO8601>"
}
```

**Behavior:**
- Generates 32-byte cryptographically random challenge
- Builds canonical `clientDataJSON`
- Computes `clientDataHash = SHA256(clientDataJSON)`
- Stores `(keyID, flowID) → { clientDataHash, verifyRunID, expiresAt, used }`
- Returns `clientDataHash` and `expiresAt`

**Write-once immutable:** Each `(keyID, flowID)` pair can have exactly one `clientDataHash`. Subsequent requests are rejected with `409 Conflict`.

### POST /app-attest/verify

Verifies an assertion signature using stored `clientDataHash` and `publicKeyX963`.

**Request:**
```json
{
  "keyID": "<base64>",
  "flowID": "<uuid>",
  "assertionObject": "<base64>",
  "verifyRunID": "<optional-uuid>"
}
```

**Response:**
```json
{
  "status": "verified" | "rejected",
  "reason": "<optional>"
}
```

**Behavior:**
1. Enforces identity bindings (A, B, C, D) before verification
2. Loads stored `clientDataHash` for `(keyID, flowID)` (consumes on success)
3. Loads stored `publicKeyX963` for `(keyID, flowID)`
4. Decodes assertion CBOR to extract `authenticatorData` and `signatureDER`
5. Performs dual DIGEST verification attempts
6. Logs `[SIX_VALUES]` block matching frontend format
7. Returns verification result

**A `verified` response means:**
- The signature is cryptographically valid for the observed byte sequence
- The `clientDataHash` matches the server-issued value
- The `publicKeyX963` corresponds to the provided `keyID`

**A `verified` response does not mean:**
- The request is authorized
- The device is trusted
- The assertion is fresh (not replayed)

## Protocol Contract

For the complete end-to-end protocol specification, see:
- `docs/AppAttest-ClientDataHash.md` - Complete authority contract and API specifications
- `docs/README_VERIFICATION.md` - Verification documentation index
- `docs/CURRENT_IMPLEMENTATION.md` - Current implementation details

The README describes this service only. It does not re-specify the protocol.

## Storage

**KeyStore (Public Keys):**
- Storage: In-memory `[String: KeyStoreEntry]` (ephemeral, reset on restart)
- Key format: `"\(keyIDHex):\(flowID)"`
- Entry: `{ publicKey: Data, flowID: String, fingerprint: PublicKeyFingerprint, ... }`

**ClientDataHashStore:**
- Storage: In-memory `[String: ClientDataHashEntry]` (ephemeral, reset on restart)
- Key format: `"\(keyIDHex):\(flowID)"`
- Entry: `{ clientDataHash: Data, verifyRunID: String?, expiresAt: Date, used: Bool, ... }`

**Production note:** Storage is intentionally abstracted. Replace with persistent storage (database, filesystem, key management service) as needed.

## Logging

The service logs structured trace blocks for forensic analysis:

- `[KEY_REGISTERED]` - Public key fingerprint at registration
- `[CLIENT_DATA_HASH]` - Hash generation and storage
- `[VERIFY_TRACE][TRANSPORT]` - Assertion object integrity
- `[VERIFY_TRACE][CLIENT_DATA_HASH]` - Stored hash integrity
- `[VERIFY_TRACE][KEY_IDENTITY]` - Public key identity and lineage
- `[VERIFY_TRACE][DECODED]` - Decoded authenticatorData and signature
- `[VERIFY_TRACE][DIGESTS]` - Dual verification attempts
- `[SIX_VALUES]` - Six-value block matching frontend format

See `docs/AppAttest-ClientDataHash.md` for complete logging specification.

## Deployment

### Deployment System

This project uses a deployment system with **hard invariants** to prevent "wrong binary running" bugs. The deploy script enforces:

1. **Build must succeed** - Service only restarts if build completes successfully
2. **Binary must exist** - Verifies binary exists and is executable after build
3. **Binary hash must change** - Service only restarts if binary actually changed
4. **Service logs binary identity** - Every startup logs `exe_path`, `binary_sha256`, `binary_timestamp`

See `DEPLOYMENT_INVARIANTS.md` and `DEPLOYMENT_EXPLANATION.md` for complete details.

### Deploying

**Always use the deploy script:**

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/deploy.sh
```

On ARM (e.g. Orange Pi), the **link phase** can take 5–15 minutes with no `swiftc` in `ps` — that’s normal. Run `./scripts/link-heartbeat.sh` in another terminal to confirm the build is alive. See `docs/BUILD_LINK_PHASE.md`.

**Fast builds when testing:** `./scripts/build-fast.sh` (inner loop; 90% of the time) or `SKIP_CLEAN=1 ./scripts/deploy.sh` (outer loop). Full `./scripts/deploy.sh` is ceremony. Optional aliases: `sf`, `sd`, `sdc` — see `docs/BUILD_LINK_PHASE.md` § Fast builds.

The script will:
- Clean build directory (skipped if `SKIP_CLEAN=1`)
- Build release binary (product-only, skips tests)
- Verify binary exists
- Compute SHA256 hash
- Compare to last deployed hash
- Only restart service if hash changed
- Log everything

**Never manually restart the service after editing code.** Use the deploy script.

### Verify Running Binary

After deployment, verify the binary matches your source. For the full three-layer status-from-Mac flow, see **Remote observability (Status from Mac)** below.

```bash
# Check logs for binary identity
sudo journalctl -u appattest-backend -n 20 | grep "CANARY"

# Check health endpoint
curl http://localhost:8080/health

# Compare hashes
cat .deployed_binary_hash
sha256sum .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

The `CANARY` log entry includes:
- `exe_path` - Full path to running binary
- `binary_sha256` - SHA256 hash of the binary
- `binary_timestamp` - File modification time
- `binary_size_bytes` - File size

### View Logs

```bash
sudo journalctl -u appattest-backend -f
```

### Initial Setup

If setting up for the first time:

1. **Install systemd service:**
   ```bash
   sudo cp /home/orangepi/Developer/appattest-backend/scripts/orangepi_run.sh /usr/local/bin/
   sudo systemctl enable appattest-backend
   ```

2. **Deploy:**
   ```bash
   cd /home/orangepi/Developer/appattest-backend
   ./scripts/deploy.sh
   ```

## Remote Observability (Status from Mac)

The service implements a **three-layer remote observability model** that allows you to verify service health and identity from your Mac without SSH. This is operator-grade introspection, not iOS debug logging.

**Quick status check:**

```bash
# Copy scripts/status_from_mac.sh to your Mac, then:
./scripts/status_from_mac.sh 10.0.0.108
```

### Layer 1: Process Reality

**Question:** "Is the service alive?"

```bash
ssh orangepi@10.0.0.108 "systemctl status appattest-backend --no-pager"
```

**Tells you:**
- Is systemd running the service
- Did it crash-loop
- When it last started

This is pure OS truth. No application-level lies possible.

### Layer 2: Binary Identity

**Question:** "Which exact binary is running?"

From your Mac:

```bash
# Get binary hash from health endpoint
curl -s http://10.0.0.108:8080/health | jq -r '.buildSha256'

# Compare with deployed hash on Pi
ssh orangepi@10.0.0.108 "cat ~/Developer/appattest-backend/.deployed_binary_hash"
```

**If hashes match:**
- You are running the binary you think you are
- No "wrong build" bugs
- No phantom code paths

If `buildSha256` from `/health` ≠ `.deployed_binary_hash`, the system is wrong, not you. Stop and fix.

This is the layer most teams never implement and then suffer for years.

### Layer 3: Semantic State

**Question:** "Is the service behaving meaningfully?"

```bash
curl -s http://10.0.0.108:8080/health | jq
```

**Response includes:**

| Field | Meaning |
|-------|---------|
| `status` | `"ok"` if healthy |
| `buildSha256` | Binary identity (Layer 2) |
| `buildTime` | Binary timestamp (Layer 2) |
| `storageBackend` | `"RAM"` (ephemeral) or `"persistent"` |
| `keyCount` | `(keyID, flowID)` entries in KeyStore |
| `clientDataHashCount` | Stored clientDataHash entries |
| `uptimeSeconds` | Process uptime in seconds |
| `lastVerifyRunIDSeen` | Most recent verifyRunID in generate/consume; `null` if none |

**From your Mac you can answer:**
- Is it warm or freshly restarted? (check `uptimeSeconds`)
- Has it seen real traffic? (check `keyCount`, `clientDataHashCount`)
- Is state accumulating or draining? (compare counts over time)
- Are verify flows actually reaching it? (check `lastVerifyRunIDSeen`)

### Health Response (Full Example)

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "ok",
  "buildSha256": "<64-char hex>",
  "buildTime": "<ISO8601>",
  "storageBackend": "RAM",
  "keyCount": 0,
  "clientDataHashCount": 0,
  "uptimeSeconds": 123.45,
  "lastVerifyRunIDSeen": null
}
```

`buildSha256` / `buildTime` = layer 2 (binary identity). The rest = layer 3 (semantic).

## Debug Forensics (DEV-ONLY)

When verification fails, you can enable detailed forensic output to diagnose byte-level mismatches. This is **DEV-ONLY** and must not be enabled in production.

### Enable Forensics

Set environment variable `APP_ATTEST_DEBUG_FORENSICS`:

- `APP_ATTEST_DEBUG_FORENSICS=1` - Include forensics in **failure responses only**
- `APP_ATTEST_DEBUG_FORENSICS=2` - Include forensics in **all responses** (success and failure)

```bash
# Enable for failures only
export APP_ATTEST_DEBUG_FORENSICS=1

# Restart service
sudo systemctl restart appattest-backend
```

### Forensics Response Format

When enabled, failed verification responses include a `forensics` object with byte-level truth:

```json
{
  "status": "rejected",
  "reason": "Identity mismatch: wrong key, clientDataHash, or bytes (both verification attempts failed)",
  "forensics": {
    "requestID": "...",
    "flowID": "...",
    "keyID_sha256": "...",
    "verifyRunID": "...",
    "assertionObject_b64_len": 141,
    "assertionObject_sha256": "...",
    "authenticatorData_len": 37,
    "authenticatorData_hex": "...",
    "authenticatorData_sha256": "...",
    "signature_len": 71,
    "signature_hex": "...",
    "signature_sha256": "...",
    "storedClientDataHash_len": 32,
    "storedClientDataHash_hex": "...",
    "storedClientDataHash_sha256": "...",
    "publicKeyX963_len": 65,
    "publicKeyX963_hex": "...",
    "publicKeyX963_sha256": "...",
    "signedBytesA_len": 69,
    "signedBytesA_hex": "...",
    "signedBytesA_sha256": "...",
    "digestA_hex": "...",
    "digestA_sha256": "...",
    "signedBytesB_len": 69,
    "signedBytesB_hex": "...",
    "signedBytesB_sha256": "...",
    "digestB_hex": "...",
    "digestB_sha256": "...",
    "verifierMode": "DIGEST_ONLY",
    "verificationAttemptA": "FAIL",
    "verificationAttemptB": "FAIL",
    "errorCase": "identityMismatch"
  }
}
```

### Comparing iOS vs Backend Values

Use the forensics output to compare byte-for-byte:

1. **authenticatorData.sha256** - Must match iOS `authenticatorData.sha256`
2. **clientDataHash.sha256** - Must match iOS `clientDataHash.sha256`
3. **signedBytesA.sha256** or **signedBytesB.sha256** - One must match iOS `signedBytes.sha256`
4. **signature.sha256** - Must match iOS `signature.sha256`
5. **publicKeyX963.sha256** - Must match the key registered for this `keyID`

If all hashes match but verification fails, the issue is in digest construction or verification mode (should be DIGEST_ONLY).

### SIX_VALUES Logging

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

## Testing

Run smoke tests:

```bash
./scripts/smoke_test.sh http://10.0.0.108:8080
```

Request observability smoke test:

```bash
curl -v -X POST http://10.0.0.108:8080/debug/echo \
  -H 'Content-Type: application/json' \
  -d '{"hello":"world"}'
```

Watch logs:

```bash
echo "orangepi" | sudo -S journalctl -u appattest-backend -f --no-pager
```

## Deployment Notes

- Service binds to `0.0.0.0:8080` (LAN accessible)
- **Firewall**: Allow port 8080 for network access:
  ```bash
  sudo ufw allow 8080
  ```
- Keys and hashes are stored server-side only (never exposed to client)
- No authentication on endpoints (add middleware if needed)

**Important**: This service performs cryptographic verification only. For production deployments, add:
- API authentication/authorization middleware
- Rate limiting
- IP allowlists if needed
- Request logging and monitoring

## Network Access

The service listens on `0.0.0.0:8080` (all interfaces), which allows:
- Local: `curl http://127.0.0.1:8080/health`
- LAN: `curl http://10.0.0.108:8080/health` (if firewall allows)
- iOS app: Can reach from phone on same network

If health check works locally but not from phone, check firewall:
```bash
sudo ufw status
sudo ufw allow 8080
```

## Implementation Details

- **Decoder**: Parses CBOR and extracts fields (AppAttestDecoder package)
- **Verifier**: Performs dual DIGEST-mode signature verification
- **Key store**: Looks up public keys by `(keyID, flowID)` (RAM-backed by default)
- **Hash store**: Stores and consumes `clientDataHash` by `(keyID, flowID)` (RAM-backed by default)

Decoder implementation: https://github.com/Mikedan37/AppAttestDecoder

## Related Documentation

- `docs/AppAttest-ClientDataHash.md` - Complete authority contract
- `docs/README_VERIFICATION.md` - Verification documentation index
- `docs/CURRENT_IMPLEMENTATION.md` - Implementation details
- `docs/ASSERTION_DER_VERIFICATION_FAILURE.md` - Verification approach
- `docs/APP_ATTEST_ASSERTION_VERIFICATION_GOTCHAS.md` - Common pitfalls
- `DEPLOYMENT_INVARIANTS.md` - Deployment system technical reference
- `DEPLOYMENT_EXPLANATION.md` - How deployment invariants prevent bugs
- `docs/BUILD_LINK_PHASE.md` - Link phase on ARM (why it looks stuck, tuning, heartbeat)

---

**Status:** This service implements a reproducible cryptographic verification artifact. It does not implement trust, authorization, or policy logic.
