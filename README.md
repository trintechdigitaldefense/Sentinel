# SENTINEL

[![CI](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/trintechdigitaldefense/Sentinel/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-3.16.10-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Authorized%20defensive%20use-red)](LICENSE)
[![Status](https://img.shields.io/badge/status-pilot%20candidate-yellow)](docs/RELEASE_CHECKLIST.md)

**TrinTech Digital Defense** — continuous host monitoring and early warning for Caribbean SMBs.

> **Authorized defensive use only.** Detect · Alert · Report. No offensive capability.

**Status:** pilot candidate (v3.16.10) on main — **not** a certified production release until [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) gates are evidenced and owner-approved.

---

## What Sentinel does

| Capability | Implementation status | Notes |
|------------|----------------------|--------|
| FIM (baseline + check) | Implemented · tested (partial) | Mode/owner/SUID; realtime needs `inotify-tools` |
| Persistence hunting | Implemented · tested (partial) | Cron, systemd, keys, LD_PRELOAD surfaces |
| Reverse-shell / behavioral | Implemented · tested (partial) | Heuristics — not proof of compromise alone |
| Canary / deception files | Implemented | Tracked decoys; missing tracked paths alert |
| Host firewall control plane | Implemented · dry-run default | Confirm required to apply; lockout guard |
| SSH brute-force blocking | Implemented · **auto_block off by default** | Opt-in autonomy |
| Multi-channel alerts | Implemented · tested (partial) | Dedup, quiet hours, offline queue |
| Critical alert persistence | Implemented · tested | Survive restarts until ACK |
| Local dashboard | Implemented · authz tests | Loopback + view-only defaults; token auth |
| Doctor / go-live | Implemented | Install-health — not a production certification |
| SIEM / Splunk HEC | Implemented · tested (partial) | Optional; disabled until configured |
| Cases / evidence packs | Implemented | Hash = post-export integrity, not legal CoC alone — see [docs/EVIDENCE_HASH.md](docs/EVIDENCE_HASH.md) |
| MSP central / agent keys | Implemented | Requires correct module load; see audit |

Labels mean: code is present and exercised in automated tests where noted. They do **not** mean exhaustive detection coverage or field validation on your network.

---

## Architecture (host)

```
Client host
  ├─ sentinel.py          menu + CLI + hunt orchestration
  ├─ modules/             detection, firewall, alerts, dashboard, cases
  ├─ ~/.sentinel/config.json   (mode 0600 when written by setup)
  └─ ~/.sentinel/data/    baselines, canaries, queues, critical store
```

Optional: systemd service, local dashboard (default `127.0.0.1`), MSP central.

---

## Install (safe path)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py doctor
```

Or:

```bash
bash install.sh
```

**Defaults are non-destructive.** `install.sh` / `setup.py` fast-forward only.  
Destructive recovery (discards uncommitted work) only when you set:

```bash
SENTINEL_RECOVER_SYNC=1 bash install.sh
```

Optional realtime FIM:

```bash
sudo apt-get install -y inotify-tools
```

Always-on (Linux with systemd):

```bash
python3 sentinel.py service-install
python3 sentinel.py doctor
```

Supported: **Python 3.10+**, Linux (primary). Termux/Android containers may lack `/proc` net or systemd — doctor will WARN.

---

## Daily use

| Command | Purpose |
|---------|---------|
| `python3 sentinel.py` | Interactive numbered menu |
| `python3 sentinel.py start` | One scan + continuous hunt |
| `python3 sentinel.py hunt` | Hunt loop only |
| `python3 sentinel.py doctor` | Health / config checks |
| `python3 sentinel.py go-live` | Baselines + canaries bootstrap |
| `python3 sentinel.py deception` | Deploy decoys |
| `python3 sentinel.py integrity` | FIM baseline |
| `python3 sentinel.py dashboard` | Local UI (token URL printed) |
| `python3 sentinel.py monitor` | Real-time threat poll (CLI) |
| `python3 sentinel.py service-install` | Background/service install |

---

## Security defaults (current)

| Control | Default |
|---------|---------|
| SSH `auto_block` | **false** (opt-in) |
| Firewall apply | **dry-run** until confirmed |
| Dashboard bind | **127.0.0.1** |
| Dashboard `allow_control` | **false** (viewer) |
| Config file mode | **0600** on write |
| Self-integrity baseline | **0600**, atomic write |

Dashboard: shareable token **cannot enable** controls; set `dashboard.allow_control: true` on the host if operators need actions.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

---

## Testing

```bash
pip install -r requirements.txt ruff pytest
pytest -q tests/
bash -n install.sh
python scripts/firewall_smoke.py
```

Details: [docs/TESTING.md](docs/TESTING.md).  
CI runs compile-all, future-import guard, ruff, firewall smoke, pytest on PRs to `main`.

**Latest local verification on hardening branch:** `pytest -q tests/` → **131+ passed** (Milestone 4). Re-run after pull for your tree.

---

## Documentation

| Doc | Purpose |
|-----|---------|
| [INSTALL.md](INSTALL.md) | Install, upgrade, recovery |
| [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) | Findings register |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Release gates |
| [docs/FEATURE_INVENTORY.md](docs/FEATURE_INVENTORY.md) | Capability inventory |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model |
| [docs/EVIDENCE_HASH.md](docs/EVIDENCE_HASH.md) | What evidence hashes prove |
| [CHANGELOG.md](CHANGELOG.md) | User-visible changes |
| [docs/SALES_PACK.md](docs/SALES_PACK.md) | Pilot sales materials |

---

## Known limitations

- Heuristic detections (shells, entropy tripwires) can false-positive; treat as leads, not verdicts.
- Realtime FIM is reduced without `inotifywait` (`visibility_status().incomplete`).
- Query-string dashboard tokens can leak via logs/Referer (prefer Bearer; tracked as H-04).
- Live firewall **apply** and third-party SIEM delivery are not fully exercised in CI.
- Doctor “install OK” is **not** a production certification.

---

## License

Authorized defensive use only — **TrinTech Digital Defense**. See [LICENSE](LICENSE).
