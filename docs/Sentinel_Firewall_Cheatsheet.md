# SENTINEL Host Firewall — Overview & Cheatsheet (13.1)

**TrinTech Digital Defense · v3.7.1** · Authorized defensive use only.

## Overview

Host packet-filter control on the agent machine (nftables / iptables). Block IPs/CIDRs, allow/deny ports, profiles, apply-managed after reboot, audit trail.

**Not** a perimeter/router firewall.

## Safe sequence

1. `python3 scripts/apply_firewall_cli.py`
2. `python3 sentinel.py firewall status`
3. `python3 sentinel.py firewall backup`
4. Dry-run: `firewall block 203.0.113.10`
5. Apply: `firewall block 203.0.113.10 --confirm`
6. After reboot: `firewall apply-managed --confirm`
7. `firewall audit` · `firewall doctor`

## Commands

| Command | Purpose |
|---------|---------|
| status | Backend + preview |
| block / unblock | DROP source IP or CIDR |
| allow-port / deny-port | Port policy |
| profile hardening|web_server|ssh_only|lab_lockdown | Profiles |
| apply-managed | Re-apply saved rules |
| enable / disable | Managed plane |
| backup / managed / audit / doctor / ensure | Ops |

*DEFEND. DETECT. DOMINATE.*
