# Phase 1 — Wired into Engine (v2.2.0)

## What was wired

| Feature | Integration |
|---------|-------------|
| Quiet mode | `send_alert()` calls `quiet_should_emit()` before logging |
| Auto-quarantine | Critical alerts trigger `auto_quarantine()` (kill PID, block IP, evidence under `data/quarantine/`) |
| Canary beacons | Decoys get `SENTINEL-CANARY-ID` + optional beacon URL; central `GET /canary/beacon?id=` |
| Agent headers | `tls_agent_headers()` for token + phase header |
| Onboard | `sentinel onboard --client NAME [--subnets x.x.x.x/24]` |
| Quiet toggle | `sentinel quiet on\|off` |
| Self-check | `sentinel phase1` |
| Quarantine status | `sentinel quarantine --status` |

## Install engine

```bash
python3 restore_v22.py
```

## Verify

```bash
python3 sentinel.py phase1
python3 sentinel.py onboard --client "Acme"
python3 sentinel.py quiet on
```

See ROADMAP.md for Phases 2–4.
