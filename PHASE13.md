# Phase 13.1 — Host Firewall Control Plane (enhanced)

**Sentinel 3.7.1** · TrinTech Digital Defense · 2026-10-24

## Scope

Host firewall manager (nftables preferred, iptables fallback) on the agent host.

**Not** a perimeter router/firewall appliance.

## Enhancements (13.1)

- IP **and CIDR** blocks with strict validation
- `apply-managed` re-apply after reboot
- `enable` / `disable` managed plane
- `lab_lockdown` profile
- `max_blocks` safety limit
- `response_actions.block_ip` routes through this plane
- `setup.py` + `apply_firewall_cli.py` wiring
- Richer status/doctor/audit

## Commands

See `docs/Sentinel_Firewall_Cheatsheet.md` and the PDF cheatsheet.
