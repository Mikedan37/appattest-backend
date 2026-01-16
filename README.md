# AppAttest Backend Service

Vapor backend service for App Attest assertion verification. Integrates AppAttestDecoder and AppAttestValidator as Swift Package dependencies.

## Architecture

- **Single endpoint**: `POST /app-attest/verify`
- **Decoder**: Parses assertion objects and reconstructs Sig_structure (server-side, single source of truth)
- **Validator**: Pure cryptographic signature verification
- **Key Store**: Server-side public key lookup by keyID

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

```bash
curl http://10.0.0.108:8080/health
```

Response:
```json
{"status":"ok"}
```

### Verify Assertion

```bash
curl -X POST http://10.0.0.108:8080/app-attest/verify \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "your-key-id",
    "assertionObject": "...",
    "clientDataHash": "..."
  }'
```

Response:
```json
{
  "status": "verified|rejected",
  "reason": "optional string"
}
```

## Key Store

Public keys are stored in `/opt/appattest/keys/<keyID>.pub` as base64-encoded 65-byte uncompressed keys (0x04 || X || Y).

Example:
```bash
echo "BASE64_ENCODED_65_BYTE_KEY" > /opt/appattest/keys/my-key-id.pub
```

## Testing

Run smoke tests:

```bash
./scripts/smoke_test.sh http://10.0.0.108:8080
```

## Security Notes

- Service binds to `0.0.0.0:8080` (LAN accessible)
- **Firewall**: Allow port 8080 for network access:
  ```bash
  sudo ufw allow 8080
  ```
- Keys are stored server-side only (never exposed to client)
- No authentication on endpoints (add middleware if needed)

## Network Access

**Important**: The service listens on `0.0.0.0:8080` (all interfaces), which allows:
- Local: `curl http://127.0.0.1:8080/health` ✅
- LAN: `curl http://10.0.0.108:8080/health` ✅ (if firewall allows)
- iOS app: Can reach from phone on same network ✅

If health check works locally but not from phone, check firewall:
```bash
sudo ufw status
sudo ufw allow 8080
```

## TODO

1. Integrate actual AppAttestDecoder package API (currently placeholder)
2. Add IP allowlist middleware if needed
3. Add request logging (hashes only, no raw data)
