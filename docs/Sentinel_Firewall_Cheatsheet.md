# SENTINEL — Host Firewall Cheatsheet

**TrinTech Digital Defense · Phase 13 · v3.7.0**  
Authorized defensive use only.

## Overview

Host packet-filter control (nftables preferred, iptables fallback) on the agent machine.

**Not** a perimeter/router firewall (pfSense/FortiGate).

**Safety:** dry-run by default. Add `--confirm` to apply. Localhost IPs refused.  
Audit: `~/.sentinel/data/firewall_audit.jsonl`

## Commands

| Command | What it does |
|---------|----------------|
| `sentinel firewall status` | Backend + rules preview |
| `sentinel firewall block <ip>` | Dry-run block source IP |
| `sentinel firewall block <ip> --confirm` | Apply DROP |
| `sentinel firewall unblock <ip> --confirm` | Remove managed block |
| `sentinel firewall allow-port 443 --confirm` | ACCEPT tcp/443 |
| `sentinel firewall deny-port 445 --confirm` | DROP tcp/445 |
| `sentinel firewall profiles` | List profiles |
| `sentinel firewall profile hardening` | Dry-run deny 135/139/445/3389 |
| `sentinel firewall profile hardening --confirm` | Apply |
| `sentinel firewall backup` | Snapshot ruleset |
| `sentinel firewall managed` | Managed IPs/ports |
| `sentinel firewall audit` | Recent audit events |
| `sentinel firewall doctor` | Health |
| `python3 -m modules.firewall status` | Module entrypoint |

## Profiles

| Profile | Intent |
|---------|--------|
| default | Track managed blocks only |
| hardening | Deny 135,139,445,3389/tcp |
| web_server | Allow 80/443 tcp |
| ssh_only | Allow 22 tcp (keep console access) |

## Safe sequence

1. `sentinel firewall status`
2. `sentinel firewall backup`
3. Dry-run change (no `--confirm`)
4. Apply with `--confirm` (needs privileges)
5. `sentinel firewall audit`

*DEFEND. DETECT. DOMINATE.* 🇹🇹
