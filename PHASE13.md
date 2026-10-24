# Phase 13 — Host Firewall Control Plane

**Sentinel 3.7.0** · TrinTech Digital Defense · 2026-10-24

## Scope (honest)

Host firewall manager on the agent machine (nftables preferred, iptables fallback).

**Not** a perimeter router/firewall appliance.

## Features

- Block / unblock source IPs (INPUT)
- Allow / deny ports
- Profiles: default, hardening, web_server, ssh_only
- Dry-run by default; `--confirm` applies
- Audit log + managed block list + rule backup

## Commands

```bash
python3 -m modules.firewall status
python3 -m modules.firewall block 203.0.113.10
python3 -m modules.firewall block 203.0.113.10 --confirm
python3 -m modules.firewall allow-port 443 --confirm
python3 -m modules.firewall profile hardening
python3 -m modules.firewall backup
python3 -m modules.firewall audit
python3 -m modules.firewall doctor
python3 sentinel.py firewall status
```

## Safety

- Refuses localhost / empty IPs
- Audit: `~/.sentinel/data/firewall_audit.jsonl`
- State: `~/.sentinel/data/firewall/managed_blocks.json`
