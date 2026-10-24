# SENTINEL v3.7.0

[![ci](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml)

**TrinTech Digital Defense** — continuous monitoring and early warning for Caribbean SMBs.

Authorized defensive use only. See [LICENSE](LICENSE).

## What it does

- **Host firewall control plane** (nftables/iptables): block IPs, allow/deny ports, profiles, audit (Phase 13)
- File integrity monitoring (FIM) and persistence hunting
- Reverse-shell / suspicious process detection
- Canary deception (digital tripwires), optional canary SMB share
- Multi-channel alerts (WhatsApp, email, webhook, syslog)
- Local dashboard (admin / viewer roles) and plain-language PDF reports
- Optional MSP central server with per-agent API keys
- Read-only connectors (Sentinel local + Wazuh skeleton)
- Case / triage workflow with evidence packs
- Backup / restore, Docker packaging, Windows agent

## Current status

**Phases 0–13** (2026-10-24) — host firewall control plane shipped.

See [ROADMAP.md](ROADMAP.md), [PHASE13.md](PHASE13.md).

## Install

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 scripts/apply_firewall_cli.py   # wires `sentinel firewall`
python3 scripts/firewall_smoke.py
python3 sentinel.py doctor
```

## Host firewall (Phase 13)

Host-level packet filter control on the agent machine — **not** a perimeter/router firewall.

```bash
python3 sentinel.py firewall status
python3 sentinel.py firewall block 203.0.113.10          # dry-run
python3 sentinel.py firewall block 203.0.113.10 --confirm
python3 sentinel.py firewall profile hardening           # dry-run
python3 sentinel.py firewall backup
python3 -m modules.firewall doctor
```

Cheatsheet: [docs/Sentinel_Firewall_Cheatsheet.md](docs/Sentinel_Firewall_Cheatsheet.md) · [PHASE13.md](PHASE13.md)

## CLI shortcuts

| Command | Purpose |
|---------|---------|
| `python3 sentinel.py` | Numbered menu |
| `firewall status` | Host firewall control plane |
| `start` / `scan` | Network scan + deception |
| `hunt` | Continuous persistence hunting |
| `deception` | Deploy canaries |
| `integrity` | FIM baseline / check |
| `doctor` | Health check |
| `dash` / `dashboard` | Local control UI |
| `cases list` | Open cases |
| `alerts` | List / triage alerts |

## Cases

```bash
python3 sentinel.py cases list
```

## License

Authorized defensive use only — TrinTech Digital Defense. See [LICENSE](LICENSE).
