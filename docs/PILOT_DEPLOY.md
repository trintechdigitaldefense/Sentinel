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

## Multi-host (optional) — transport warning

The legacy enrollment example below uses plain HTTP on port 8743. The current main-branch remote-agent default also constructs an `http://` central URL when no explicit central URL is configured. Do **not** use that default across a LAN, VPN, public network, or other untrusted path: the shared-token/agent traffic is not protected by TLS.

For network-facing central-agent deployment, the current implementation requires a valid TLS certificate and private key and fails closed when TLS setup is missing or invalid. Network listeners reject the legacy shared-token mode and require per-agent credentials; agents use HTTPS with certificate verification. Automated SSH enrollment requires a preverified host key in the operator's known_hosts file. Before client use, provision and validate the certificate/SAN/CA chain, test agent enrollment and key revocation, verify the systemd service under the target OS, and perform a controlled rollback drill. The service lifecycle (install, start, restart, stop and start) is now exercised in a disposable Ubuntu/systemd CI container; this does not replace validation on the client's actual OS. Dashboard TLS is a separate control and remains subject to the reverse-proxy procedure in `DASHBOARD_TLS.md`.

The remote dashboard TLS procedure in [DASHBOARD_TLS.md](DASHBOARD_TLS.md) protects the dashboard path; it does not automatically secure the separate agent transport.

## Limits to tell the client
- One sensor ≠ every laptop fully protected
- Android may be monitor-only for firewall
- Heuristics can false-positive; use suppressions
