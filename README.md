# AppAttest Backend Service

A backend service that verifies Apple App Attest assertions.

This repository records a specific verification behavior and the code required to reproduce it.

This is an independent implementation. It is not official, not endorsed, and not intended to represent best practices beyond the specific behavior it implements.

## What This Service Does

The service performs three steps:
1. Decode App Attest assertion objects
2. Reconstruct the byte sequence used for signing
3. Verify the ES256 signature over those bytes

That is the entire scope.

## Notes

This repository documents one concrete verification behavior observed while implementing App Attest:

- The assertion signature verifies over the byte sequence:
  ```
  authenticatorData || clientDataHash
  ```

Several verification approaches were evaluated.
Only one produced a valid signature verification in this implementation.

The code isolates this behavior so it can be inspected, tested, and reproduced.

## Verification Behavior

For assertions, the service verifies the signature over:

```
authenticatorData || clientDataHash
```

This is the byte sequence used for signing.

The service performs a single ES256 verification and returns the result.

No additional interpretation is applied.

## Security Boundaries

This service verifies cryptographic validity only.

It does not answer:
- Whether a device should be trusted
- Whether a request should be allowed
- Whether a user is authenticated
- Whether an assertion is fresh or unique

### What the Service Provides
- Signature verification for App Attest assertions
- Detection of tampering or mismatched inputs
- A clear view of what bytes are verified

### What the Service Does Not Provide
- Device trust decisions
- User authentication
- Authorization
- Replay protection
- Rate limiting
- Abuse prevention
- Key rotation or revocation
- High availability
- Persistent storage guarantees

## Architecture Overview

**Endpoints:**
- `POST /app-attest/register` - Extracts and stores a public key from an attestation object
- `POST /app-attest/verify` - Verifies an assertion signature against a previously registered key

**Components:**
- Decoder: Parses CBOR and extracts fields (AppAttestDecoder package)
- Validator: Performs signature verification
- Key store: Looks up public keys by keyID (RAM-backed by default)

Decoder implementation: https://github.com/Mikedan37/AppAttestDecoder

## Setup

### 1. Bootstrap Orange Pi

```bash
ssh orangepi@10.0.0.108
cd /opt/appattest-backend
./scripts/orangepi_bootstrap.sh
```

### 2. Deploy from Mac

```bash
cd /path/to/appattest-backend
./scripts/orangepi_deploy.sh
```

### 3. Install Systemd Service

On Orange Pi:

```bash
sudo cp deploy/appattest-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable appattest-backend
sudo systemctl start appattest-backend
```

### 4. View Logs

```bash
journalctl -u appattest-backend -f
```

## API

### Health Check

Simple endpoint to verify the service is running. Does not perform any cryptographic operations.

```bash
curl http://10.0.0.108:8080/health
```

Response:
```json
{"status":"ok"}
```

### Register Attestation

**What it does**: Extracts the public key from an App Attest attestation object and stores it server-side, keyed by `keyID`.

**What it does NOT do**: 
- Does not verify the attestation signature (that's the client's responsibility)
- Does not establish device trust
- Does not authenticate the caller

**Request:**
```bash
curl -X POST http://10.0.0.108:8080/app-attest/register \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "base64-key-id",
    "attestationObject": "base64-attestation-object",
    "clientDataHash": "base64-client-data-hash"
  }'
```

**Success Response:**
```json
{
  "status": "registered",
  "reason": null
}
```

**Failure Response:**
```json
{
  "status": "rejected",
  "reason": "Failed to decode attestation object"
}
```

**Common rejection reasons:**
- Invalid base64 encoding
- Attestation format is not "apple-appattest"
- Missing or invalid public key in attestation
- Storage failure (if using filesystem storage)

### Verify Assertion

**What it does**: Verifies that an assertion signature is cryptographically valid for the given `keyID` and `clientDataHash`.

**What it does NOT do**:
- Does not verify the assertion was generated recently (no timestamp checking)
- Does not verify the assertion hasn't been reused (no replay protection)
- Does not authenticate the caller
- Does not authorize the request

**Request:**
```bash
curl -X POST http://10.0.0.108:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "base64-key-id",
    "assertionObject": "base64-assertion-object",
    "clientDataHash": "base64-client-data-hash"
  }'
```

**Success Response:**
```json
{
  "status": "verified",
  "reason": null
}
```

The signature is cryptographically valid. The assertion was signed by the private key corresponding to the stored public key for this `keyID`, over the exact bytes `authenticatorData || clientDataHash`.

**Failure Response:**
```json
{
  "status": "rejected",
  "reason": "signature invalid"
}
```

**Common rejection reasons:**
- Public key not found for `keyID` (must register first)
- Invalid base64 encoding
- Assertion is not a valid CBOR map
- Missing `authenticatorData` or `signature` in assertion
- Signature does not verify (tampering detected or wrong bytes)
- Invalid signature format

A `verified` response indicates cryptographic correctness only. It does not indicate:
- The request is authorized
- The device is trusted
- The user is authenticated
- The assertion is fresh (not replayed)

## Key Store

Public keys are stored server-side and looked up by keyID.

**Default implementation**: RAM-backed storage (in-memory dictionary) for testing and development. Keys are ephemeral and reset on server restart.

**Production note**: Storage is intentionally abstracted. Replace with:
- Filesystem-backed storage (`/opt/appattest/keys/<keyID>.pub`)
- Database (PostgreSQL, SQLite, etc.)
- Key management service (AWS KMS, HashiCorp Vault, etc.)

Keys are stored as 65-byte uncompressed format: `0x04 || X || Y` (P-256 public key).

## Testing

Run smoke tests:

```bash
./scripts/smoke_test.sh http://10.0.0.108:8080
```

## Deployment Security Notes

- Service binds to `0.0.0.0:8080` (LAN accessible)
- **Firewall**: Allow port 8080 for network access:
  ```bash
  sudo ufw allow 8080
  ```
- Keys are stored server-side only (never exposed to client)
- No authentication on endpoints (add middleware if needed)

**Important**: This service performs cryptographic verification only. For production deployments, add:
- API authentication/authorization middleware
- Rate limiting
- IP allowlists if needed
- Request logging and monitoring

## Network Access

**Important**: The service listens on `0.0.0.0:8080` (all interfaces), which allows:
- Local: `curl http://127.0.0.1:8080/health`
- LAN: `curl http://10.0.0.108:8080/health` (if firewall allows)
- iOS app: Can reach from phone on same network

If health check works locally but not from phone, check firewall:
```bash
sudo ufw status
sudo ufw allow 8080
```

