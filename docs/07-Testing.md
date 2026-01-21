# Testing

This chapter describes how to test the service.

## Single Flow Verification Test

### Test: `test_full_verification_flow_happy_path`

This test exercises the complete verification flow:

1. **Registration**: POST /app-attest/register
   - Extracts and stores public key
   - Returns flowID

2. **Challenge Generation**: GET /app-attest/challenge
   - Issues challenge bound to (keyID, flowID)
   - Returns challenge_b64, challenge_id, expiresAt

3. **Verification**: POST /app-attest/verify
   - Verifies assertion using stored public key and challenge
   - Returns status: "verified" when signature is valid
   - Marks challenge as consumed

4. **Challenge Consumption**: Attempt to reuse consumed challenge
   - Verifies challenge cannot be reused (one-time-use)

### What This Test Proves

- Registration succeeds and returns flowID
- Challenge is issued and stored
- Verification returns status: "verified" when signature is valid
- Challenge is marked as consumed after successful verification
- Consumed challenges cannot be reused

### What This Test Does NOT Prove

- Security guarantees (authorization, trust, policy compliance)
- Replay protection beyond protocol-level challenge consumption
- Freshness validation beyond 5-minute TTL
- Certificate chain validation
- Key source verification

This test validates protocol behavior only. It does not validate security properties beyond protocol-level enforcement.

## Running Tests

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

## Health Check

Check service health:

```bash
curl http://localhost:8080/health
```

**Expected Response:**
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
