# SENTINEL — Threat Model (summary)

**Scope:** Host-based continuous monitoring and early warning for Linux SMB endpoints (Caribbean SMB / MSP deployments).

**Not in scope:** Perimeter firewall, active exploitation, offensive tooling, guaranteed prevention of all attacks.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Host integrity (binaries, configs, cron, systemd) | Compromise foothold |
| SSH access & authorized_keys | Persistent remote access |
| Credentials / canary decoys | Detect hands-on-keyboard |
| Sentinel itself | Blind the defender |
| Alert channel (WhatsApp/email) | Operator notification |

## Adversary goals (SMB-relevant)

1. Land a reverse shell or webshell after phishing / exposed service
2. Plant persistence (cron, systemd timer, authorized_keys, LD_PRELOAD)
3. Disable or ignore the monitoring agent
4. Exfiltrate data; ransomware staging

## Sentinel controls (mapped)

| Threat | Control |
|--------|---------|
| Reverse shell | Cmdline patterns + behavioral (TTY+TCP, deleted exe, web→shell) |
| Persistence | Cron / systemd / timers / keys / LD_PRELOAD baselines |
| Privilege escalation | SUID inventory + mode/owner FIM |
| Silent file change | FIM baseline + optional inotify realtime |
| Brute-force SSH | Failure tracking + host firewall block (dry-run default) |
| Agent tamper | Self-FIM on engine + core modules |
| Alert fatigue | Dedup + quiet hours + offline queue |
| Operator lockout | Firewall lockout guard (refuse block of SSH client IP) |

## Trust boundaries

- Config and data under `~/.sentinel/` (owner-only permissions)
- Firewall apply requires explicit `--confirm`
- Central/MSP agents use per-agent keys (when central is deployed)
- Authorized defensive use only — see LICENSE

## Residual risk

- Restricted environments (Termux/proot) may lack `/proc/net/tcp` or nft/iptables
- Without `inotify-tools`, FIM is polling-based during hunt intervals
- WhatsApp depends on third-party API availability; offline queue mitigates
