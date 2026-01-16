# Deployment Commands

## On Mac

### Deploy to Orange Pi
```bash
cd /path/to/appattest-backend
./scripts/orangepi_deploy.sh
```

## On Orange Pi (10.0.0.108)

### 1. Bootstrap (first time only)
```bash
cd /opt/appattest-backend
./scripts/orangepi_bootstrap.sh
```

### 2. Enable and start systemd service
```bash
sudo cp deploy/appattest-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable appattest-backend
sudo systemctl restart appattest-backend
```

### 3. View logs
```bash
journalctl -u appattest-backend -f
```

### 4. Test health endpoint
```bash
curl http://127.0.0.1:8080/health
```

### 5. Test verify endpoint
```bash
curl -X POST http://127.0.0.1:8080/app-attest/verify-assertion \
  -H "Content-Type: application/json" \
  -d '{
    "keyID": "test-key",
    "assertionObjectBase64": "dGVzdA==",
    "clientDataHashBase64": "dGVzdA=="
  }'
```

### 6. Run smoke tests
```bash
cd /opt/appattest-backend
./scripts/smoke_test.sh
```

## Notes

- Service listens on `0.0.0.0:8080` (LAN accessible)
- Public keys: `/opt/appattest/keys/<keyID>.pub` (base64, 65 bytes)
- AppAttestDecoder integration: Replace placeholders in `AssertionDecoder.swift` with actual API
