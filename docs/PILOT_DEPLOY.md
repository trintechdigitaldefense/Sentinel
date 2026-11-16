# Sentinel pilot deployment (TrinTech)

## Goal
One always-on sensor + weekly/biweekly checkups. Not full EDR on every device.

## Install
```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py autosubnet
python3 sentinel.py doctor
python3 sentinel.py   # option 1
```

## After option 1
- Dashboard URL printed (loopback + token)
- Always-on hunt via systemd or background
- Firewall plane armed (live blocks only if nft/iptables exist)

## Suppress noisy alerts
```bash
python3 sentinel.py suppress-add SUSPICIOUS_PROCESS "backup-script"
python3 sentinel.py suppress
```

## Multi-host (optional)

Network-facing central listeners must use TLS. Configure the central service with both `agent.tls_cert` and `agent.tls_key` before binding beyond loopback, and set each agent's `central_url` to an `https://` endpoint.

Use the supported SSH deployment command from the central host:

```bash
python3 sentinel.py agent-push user@HOST --identity ~/.ssh/id_ed25519
```

Generated agent bundles use a distinct expiring per-agent API key. Keep `install_agent.sh` and its `agent.key` sidecar together during transfer; the key file is mode `0600` and expires after 30 days. Do not email, publish, or commit either file. Reissue the agent credential before expiry.

## Limits to tell the client
- One sensor ≠ every laptop fully protected
- Android may be monitor-only for firewall
- Heuristics can false-positive; use suppressions
