# Changelog

## 3.7.0 — 2026-10-24

### Phase 13 — Host Firewall Control Plane
- `modules/firewall.py` — nft/iptables host FW manager (dry-run default)
- Profiles: hardening, web_server, ssh_only
- Audit log + managed blocks + rule backup
- CLI: `sentinel firewall` / `python3 -m modules.firewall`
- Tests: `tests/test_firewall.py` · smoke: `scripts/firewall_smoke.py`
- Docs: PHASE13.md · Firewall cheatsheet

## 3.6.0 — 2026-10-24

### Phase 12 — Foundations
- tenants, policy auto_response (never silent), UEBA-lite

## 3.5.1 — 2026-10-24

### Dual-connector pilot wire

## 3.5.0 — 2026-10-24

### Phase 11 — Correlation · AI assist · gated response

## 3.4.0 — 2026-10-24

### Phase 10 — Operational cadence

## 3.3.0 — 2026-10-24

### Phase 9 — MSP daily use

## 3.2.1 — 2026-10-24

### Phase 8 — Ship-ready wire

## 3.2.0 — 2026-10-24

Phases 0–7 on existing Sentinel engine.

## 3.1.0 — 2026-10-15

Trust, MSP keys, backup/restore, Docker, CI.

## 3.0.0 — 2026-10-15

Plain source tree, multi-channel alerting, central server, Windows agent.
