# Changelog

## [3.5.0] — 2026-10-25

### Product hygiene
- README rewrite: feature matrix, menu preview, full CLI table, architecture
- docs/THREAT_MODEL.md — SMB-focused control mapping
- CI: ruff critical checks, module compile, firewall smoke, pytest
- tests/test_persistence_behavioral.py — persistence, SUID, behavioral, lockout

## [3.4.0] — 2026-10-25

### Persistence expansion + behavioral shells + self-FIM
- **persistence_hunt**: systemd timers/sockets, authorized_keys drift, LD_PRELOAD create/change, profile.d, rc files
- **behavioral_shell**: deleted `/proc/pid/exe`, TTY+TCP established, web-server→shell parent anomaly
- **Self-FIM**: tracks core modules + setup.py; full-tree git updates refresh baseline; partial module change alerts
- CLI: `sentinel persistence-baseline` · `sentinel persistence` · `sentinel behavioral`

## [3.3.1] — 2026-10-25

### FIM / detection quality
- **Mode + ownership tracking** on every baselined file (FIM_MODE_CHANGE, FIM_OWNER_CHANGE)
- **SUID/SGID inventory** (`modules/fim_suid.py`): NEW_SUID, REMOVED_SUID, SUID_META_CHANGE
- **Real-time FIM** (`modules/fim_realtime.py`): single multi-path inotifywait process; polling fallback
- CLI: `python3 sentinel.py suid` · `python3 sentinel.py watch`
- `sentinel integrity` builds both content baseline and SUID inventory

## [3.3.0] — 2026-10-24

### Firewall (Phase 13.2)
- **Lockout guard**: refuses to block current/recent SSH operator IPs; `protect-operator` before hardening profiles
- **IPv6**: iptables path uses `ip6tables` for v6 targets; nft already dual-stack via `inet`
- Firewall actions logged into case system when available
- CLI: `firewall protect-operator`, `firewall operator-ips`

### Alerting
- Failed multi-channel delivery auto-enqueues to offline queue (flush via `sentinel offline flush`)


# Changelog

## 3.7.1 — 2026-10-24

### Phase 13.1 — Host Firewall enhanced
- CIDR blocks, apply-managed, enable/disable, lab_lockdown profile
- max_blocks safety, richer status/doctor
- response_actions.block_ip routes through modules.firewall
- setup.py + apply_firewall_cli wiring
- Cheatsheet PDF/MD refreshed

## 3.7.0 — 2026-10-24

### Phase 13 — Host Firewall Control Plane
- modules/firewall.py nft/iptables host FW manager

## 3.6.0 — 2026-10-24

### Phase 12 — Foundations
- tenants, policy auto_response, UEBA-lite

## 3.5.1 — 2026-10-24

Dual-connector pilot wire

## 3.0.0 — 2026-10-15

Plain source tree, multi-channel alerting, central server, Windows agent.
