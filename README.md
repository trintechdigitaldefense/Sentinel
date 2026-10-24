# SENTINEL v3.2.1

[![ci](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml)

**TrinTech Digital Defense** — continuous monitoring and early warning for Caribbean SMBs.

Authorized defensive use only. See [LICENSE](LICENSE).

## What it does

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

**Phases 0–8 complete** (2026-10-24) — ship-ready wire.

See [ROADMAP.md](ROADMAP.md), [PHASE8.md](PHASE8.md), [docs/PHASE8_ACCEPTANCE.md](docs/PHASE8_ACCEPTANCE.md).

## Install

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py             # wires cases menu + dashboard open-cases UI
python3 scripts/phase8_smoke.py
python3 sentinel.py          # interactive menu (Cases 16/17)
python3 sentinel.py doctor
```

Optional always-on:

```bash
python3 sentinel.py service-install
```

One-line installer (verify checksum first — see [VERIFY.md](VERIFY.md)):

```bash
curl -sSL https://raw.githubusercontent.com/trintechdigitaldefense/Sentinel/main/install.sh | bash
```

Docker:

```bash
docker compose up -d
```

## CLI shortcuts

| Command | Purpose |
|---------|---------|
| `python3 sentinel.py` | Numbered menu |
| `start` / `scan` | Network scan + deception |
| `hunt` | Continuous persistence hunting |
| `deception` | Deploy canaries |
| `deception --smb-share` | Opt-in canary SMB share (Linux) |
| `integrity` | FIM baseline / check |
| `doctor` | Health check |
| `dash` / `dashboard` | Local control UI (open cases) |
| `pdf` / `client-report` | PDF reports |
| `service-install` | Always-on (systemd or background) |
| `alerts` | List / triage alerts |
| `cases list` | Open cases (Phase 7/8) |
| `config` / `config --wizard` | Show or build config |
| `enroll --server URL --key KEY` | Enroll with central (gets unique agent key) |
| `backup --out file.enc` | Encrypted backup |
| `restore file.enc` | Restore from backup |
| `watchdog` | Restart hunt if it dies |
| `evidence export --case NAME` | Signed evidence bundle |
| `schedule-report weekly` | Scheduled client PDF |

## Cases (Phase 7/8)

```bash
python3 setup.py
python3 scripts/phase8_smoke.py
python3 sentinel.py cases list
python3 -c "from modules.connectors.cli import main; main(['fetch','--source','sentinel_local','--auto-case'])"
```

Dashboard: `python3 sentinel.py dash` → Open cases metric + table.

## License

Authorized defensive use only — TrinTech Digital Defense. See [LICENSE](LICENSE).
