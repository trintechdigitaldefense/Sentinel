# SENTINEL v3.1

**TrinTech Digital Defense** — continuous monitoring and early warning for Caribbean SMBs.

Authorized defensive use only. See [LICENSE](LICENSE).

## What it does

- File integrity monitoring (FIM) and persistence hunting
- Reverse-shell / suspicious process detection
- Canary deception (digital tripwires), optional canary SMB share
- Multi-channel alerts (WhatsApp, email, webhook, syslog)
- Local dashboard (admin / viewer roles) and plain-language PDF reports
- Optional MSP central server with per-agent API keys
- Backup / restore, Docker packaging, Windows agent

## Install

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py          # interactive menu
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
| `dash` / `dashboard` | Local control UI |
| `pdf` / `client-report` | PDF reports |
| `service-install` | Always-on (systemd or background) |
| `alerts` | List / triage alerts |
| `config` / `config --wizard` | Show or build config |
| `enroll --server URL --key KEY` | Enroll with central (gets unique agent key) |
| `backup --out file.enc` | Encrypted backup |
| `restore file.enc` | Restore from backup |
| `watchdog` | Restart hunt if it dies |
| `evidence export --case NAME` | Signed evidence bundle |
| `schedule-report weekly` | Scheduled client PDF |

## Config (`~/.sentinel/config.json`)

| Section | Keys |
|---------|------|
| `client_name` | Display name |
| `network` | `subnets[]`, `auto_detect` |
| `alerting` | `whatsapp`, `email`, `webhook`, `syslog`, `quiet_hours`, `dedup_minutes` |
| `response` | `enabled`, `kill_process`, `block_ip`, `disable_user` (all default **false**) |
| `threat_intel` | `enabled`, `abuseipdb_key`, `otx_key`, `cache_hours` |
| `dashboard` | `port`, `bind`, `username`, `password`, `role` (`admin`\|`viewer`), `allow_control` |
| `central` | `enabled`, `server_url`, `api_key` (per-agent after enroll) |
| `deception` | `smb_share` (default false) |
| `logging` | `level`, `json_files`, `retention_days` |
| `agent` | `shared_token`, `mode`, `agent_id` |

Validate: `python3 -c "from modules.config_schema import load_config; load_config()"`

## Central (MSP)

```bash
python3 -m sentinel_central.server --port 8443 --master-key YOUR_MASTER
# enroll each site (issues unique agent key):
python3 sentinel.py enroll --server https://host:8443 --key YOUR_MASTER
# revoke one agent:
python3 -m sentinel_central.server --revoke AGENT_ID --master-key YOUR_MASTER
```

## Backup / restore

```bash
python3 sentinel.py backup --out /path/sentinel-backup.enc
python3 sentinel.py restore /path/sentinel-backup.enc
```

## Verify releases

See [VERIFY.md](VERIFY.md) for SHA-256 checksums of tags and `install.sh`.

## Tests

```bash
pip install -r requirements.txt pytest
pytest -q
```

## Legal

For authorized security monitoring on systems you own or are contracted to protect.
Reference applicable law including the Trinidad and Tobago Cybercrime Act as relevant.

© 2026 TrinTech Digital Defense — [LICENSE](LICENSE)
