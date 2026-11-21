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

For the current main-branch implementation, do **not** start the legacy central-agent listener on a network-facing host. `modules/central_agent.py` binds to `0.0.0.0`; although a TLS helper exists, the current `start_central()` path does not apply it. This is not a loopback-only service and cannot be made safe for remote use merely by setting certificate paths. Do not advertise remote multi-host deployment as secure or client-ready until a separately reviewed implementation enforces HTTPS, certificate validation, per-agent credential handling, and fail-closed behavior on network-facing listeners. PR #8 contains proposed remediation, but it is still unmerged and is not part of this documented main-branch capability.

The remote dashboard TLS procedure in [DASHBOARD_TLS.md](DASHBOARD_TLS.md) protects the dashboard path; it does not automatically secure the separate agent transport.

## Limits to tell the client
- One sensor ≠ every laptop fully protected
- Android may be monitor-only for firewall
- Heuristics can false-positive; use suppressions
