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
```bash
python3 sentinel.py agent-key site-office-pc
# on remote: python3 sentinel.py enroll --server http://SENSOR:8743 --key <api_key>
```

## Limits to tell the client
- One sensor ≠ every laptop fully protected
- Android may be monitor-only for firewall
- Heuristics can false-positive; use suppressions
