# SENTINEL

[![CI](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-3.12.0-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Authorized%20defensive%20use-red)](LICENSE)

**TrinTech Digital Defense** — continuous host monitoring and early warning for Caribbean SMBs.

> Authorized defensive use only. Detect · Alert · Report. No offensive capability.

---

## What you get

| Capability | Detail |
|------------|--------|
| **FIM** | Content + mode/owner/SUID baseline; optional realtime via `inotifywait` |
| **Persistence** | Cron, systemd units/**timers**, `authorized_keys`, LD_PRELOAD, rc files |
| **Shells** | Cmdline patterns + **behavioral** (deleted exe, TTY+TCP, web→shell) |
| **Canaries** | Realistic decoy files; optional SMB honey share |
| **Host firewall** | nft/iptables control plane — dry-run default, **lockout guard**, IPv6 |
| **Alerts** | WhatsApp / email / webhook / syslog — dedup, quiet hours, **offline queue** |
| **Evidence** | Cases, PDF reports, evidence packs |
| **Ops** | Doctor, systemd/service-install, dashboard, backup/restore, Docker |

```
  MAIN MENU (stable)
  ------------------------------------------------------
   1   START continuous protection
   4   Deploy deception / canaries
   5   Integrity baseline (FIM + SUID)
   8   Detection tools →
  16   Pilot validation
  17   Doctor
  18   Firewall tools →
  19   Ops (PDF, dashboard, cases) →
  20   Field soak (friendly site)
```

*(Run `python3 sentinel.py` for the full numbered menu.)*

---

## Install (single path)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py doctor
```

Optional realtime FIM:

```bash
sudo apt-get install -y inotify-tools
```

Always-on:

```bash
python3 sentinel.py service-install
python3 sentinel.py doctor
```

---

## Daily use

| Command | Purpose |
|---------|---------|
| `python3 sentinel.py` | Interactive numbered menu |
| `python3 sentinel.py start` | Scan once + continuous hunt |
| `python3 sentinel.py hunt` | Hunt loop only |
| `python3 sentinel.py integrity` | Build / refresh FIM + SUID baselines |
| `python3 sentinel.py deception` | Deploy canary decoys |
| `python3 sentinel.py persistence-baseline` | Snapshot cron/systemd/keys/LD_PRELOAD |
| `python3 sentinel.py persistence` | Diff persistence surface |
| `python3 sentinel.py behavioral` | Behavioral reverse-shell scan |
| `python3 sentinel.py suid` | SUID/SGID inventory check |
| `python3 sentinel.py watch` | Realtime FIM (inotify) |
| `python3 sentinel.py firewall status` | Host firewall plane |
| `python3 sentinel.py firewall block <ip>` | Dry-run block (add `--confirm` to apply) |
| `python3 sentinel.py ssh-blocks check` | SSH brute-force scan + auto-block via firewall |
| `python3 sentinel.py ssh-blocks status` | Active SSH blocks / whitelist |
| `python3 sentinel.py firewall protect-operator --confirm` | Lockout guard ACCEPT rules |
| `python3 sentinel.py doctor` | Health check |
| `python3 sentinel.py visibility` | Devices + processes + FIM + persistence inventory |
| `python3 sentinel.py ops` | Hunt metrics, alerts, service, SSH blocks |
| `python3 sentinel.py critical status` | Unacknowledged critical alerts |
| `python3 sentinel.py critical ack <id>` | Acknowledge a critical alert |
| `python3 sentinel.py siem status` | SIEM / centralized logging status |
| `python3 sentinel.py siem test` | Emit SIEM test event |
| `python3 sentinel.py siem splunk-configure --url URL --token T` | Enable Splunk HEC |
| `python3 sentinel.py siem splunk health` | Test HEC connectivity |
| `python3 sentinel.py pilot` | Full pilot validation workflow |
| `python3 sentinel.py pilot --fix` | Pilot + create missing baselines |
| `python3 sentinel.py go-live` | Host setup: baselines + canaries + alert ship |
| `python3 sentinel.py go-live --service` | Go-live + always-on service attempt |
| `python3 sentinel.py field-soak --confirm` | Friendly-site soak (canary/sim/channels) |
| `python3 sentinel.py sim --list` | Threat-actor simulation scenarios |
| `python3 sentinel.py sim --scenario all --confirm` | Run defensive detection probes |
| `python3 sentinel.py dash` | Local dashboard |
| `python3 sentinel.py offline flush` | Replay queued alerts |

---

## Host firewall (safety)

- **Not** a perimeter/router firewall — host INPUT plane only
- **Dry-run by default** — nothing applies without `--confirm`
- **Lockout guard** refuses to block your current SSH client IP
- **IPv6** supported (`ip6tables` / nft `inet`)

```bash
python3 scripts/firewall_smoke.py    # CI + local dry-run smoke
```

Cheatsheet: [docs/Sentinel_Firewall_Cheatsheet.md](docs/Sentinel_Firewall_Cheatsheet.md)

---

## Architecture notes

- Config: `~/.sentinel/config.json` · Data/logs: `~/.sentinel/`
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Pilot workflow: [docs/PILOT.md](docs/PILOT.md)
- Threat simulation: [docs/THREAT_SIM.md](docs/THREAT_SIM.md)
- SIEM logging: [docs/SIEM.md](docs/SIEM.md)
- Splunk HEC: [docs/SPLUNK.md](docs/SPLUNK.md)
- Go-live: [docs/GO_LIVE.md](docs/GO_LIVE.md)
- Field soak: [docs/FIELD_SOAK.md](docs/FIELD_SOAK.md)
- Sales pack: [docs/SALES_PACK.md](docs/SALES_PACK.md)
- One-page runbook: [docs/RUNBOOK_ONE_PAGE.md](docs/RUNBOOK_ONE_PAGE.md) · [PDF](docs/SENTINEL_One_Page_Runbook.pdf)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Roadmap / phases: [ROADMAP.md](ROADMAP.md) · [PHASE13.md](PHASE13.md)

```
Client host
  ├─ sentinel.py (menu + hunt)
  ├─ modules/ (FIM, persistence, shells, firewall, alerts, cases…)
  ├─ ~/.sentinel/data (baselines, canaries, audit, offline queue)
  └─ optional: systemd service · dashboard :8792 · MSP central
```

---

## Development / CI

```bash
pip install -r requirements.txt ruff pytest
python scripts/firewall_smoke.py
pytest -q tests/
```

GitHub Actions runs on every push/PR to `main`: compile → ruff (critical) → firewall smoke → pytest.

---

## License

Authorized defensive use only — **TrinTech Digital Defense**. See [LICENSE](LICENSE).


## Product focus (v3.11)

Feature set is **frozen for pilot** unless a paid engagement requires a change:

1. Field soak on 1–2 friendly sites  
2. Sales pack + fixed pilot price ([docs/SALES_PACK.md](docs/SALES_PACK.md))  
3. Multi-host MSP polish only after pilot demand  

