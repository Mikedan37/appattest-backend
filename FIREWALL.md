# Firewall Setup

## Allow Port 8080

```bash
sudo ufw allow 8080
```

Or for testing only (not recommended for production):

```bash
sudo ufw disable
```

## Verify

```bash
# Check firewall status
sudo ufw status

# Test from another machine
curl http://10.0.0.108:8080/health
```

## Network Binding

The service is configured to listen on `0.0.0.0:8080` (all interfaces), which allows:
- Local access: `curl http://127.0.0.1:8080/health`
- LAN access: `curl http://10.0.0.108:8080/health`
- iOS app access from phone on same network

If you see `127.0.0.1` in the config, change it to `0.0.0.0`.
