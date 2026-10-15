# SENTINEL v3.0

**TrinTech Digital Defense** — continuous monitoring and early warning for Caribbean SMBs.

Authorized defensive use only. Not for unauthorized access or offensive operations.

## What it does

- File integrity monitoring (FIM) and persistence hunting
- Reverse-shell / suspicious process detection
- Canary deception (digital tripwires)
- Multi-channel alerts (WhatsApp, email, webhook, syslog)
- Local dashboard and plain-language PDF reports
- Optional MSP central server + Windows agent

## Quick start

```bash
# Private repo — clone with credentials, or:
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py          # interactive menu
python3 sentinel.py doctor
python3 sentinel.py hunt     # continuous protection
python3 sentinel.py dash     # local dashboard
```

One-liner (when install.sh is reachable with auth):

```bash
curl -sSL <install.sh-url> | bash
```

## CLI shortcuts

| Command | Purpose |
|---------|---------|
| `python3 sentinel.py` | Numbered menu |
| `start` / `scan` | Network scan + deception |
| `hunt` | Continuous persistence hunting |
| `deception` | Deploy canaries |
| `integrity` | FIM baseline / check |
| `doctor` | Health check |
| `dash` / `dashboard` | Local control UI |
| `pdf` / `client-report` | PDF reports |
| `service-install` | Always-on (systemd or background) |
| `alerts` | List / triage alerts (v3) |
| `config` / `config --wizard` | Show or build config |
| `enroll --server URL --key KEY` | Point agent at central |
| `watchdog` | Restart hunt if it dies |
| `report --schedule weekly` | Scheduled client PDF |

## Config (`~/.sentinel/config.json`)

Key sections:

- `network.subnets` / `auto_detect`
- `alerting.whatsapp|email|webhook|syslog` + `dedup_minutes` + `quiet_hours`
- `response.*` — containment (all default **false**)
- `threat_intel.*` — AbuseIPDB / OTX keys
- `dashboard.*` — port, bind, auth
- `central.*` — MSP server URL + API key
- `logging.level` / `retention_days`

Validate: `python3 -c "from modules.config_schema import load_config; load_config()"`

## Central (MSP)

```bash
python3 -m sentinel_central.server --port 8443 --key YOUR_SECRET
# agents:
python3 sentinel.py enroll --server https://host:8443 --key YOUR_SECRET
```

## Windows agent

```bat
cd agents
install.bat https://central:8443 YOUR_SECRET
```

## Tests

```bash
pip install -r requirements.txt pytest ruff
pytest -q
```

## License / legal

For authorized security monitoring on systems you own or are contracted to protect.
Reference applicable law including the Trinidad and Tobago Cybercrime Act as relevant.

© TrinTech Digital Defense
