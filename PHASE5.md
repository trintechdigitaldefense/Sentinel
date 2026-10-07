# SENTINEL Phase 5 — Competitive ops layer

## Features

| Command | Purpose |
|---------|---------|
| `phase5` | Self-check Phase 5 modules |
| `autosubnet` | Detect local /24 and write to config (no /8 scans) |
| `heartbeat` | Write/read `~/.sentinel/data/heartbeat.json` |
| `digest [--hours 24]` | Alert log summary → `digest_latest.json` |
| `status-json` | Machine-readable status for SIEM / scripts |
| `dashboard` | Local HTML status page (default port **8787**) |

## Install

```bash
cd Sentinel
python3 setup.py
python3 wire_phase5.py   # if setup did not wire yet
```

## Dashboard

```bash
python3 sentinel.py dashboard
# http://HOST:8787/
python3 sentinel.py dashboard --write-only
```

## Why this matters for SMBs

- **Autosubnet** — fewer failed scans on first install
- **Heartbeat** — external uptime checks
- **Digest** — daily summary for client reports
- **status-json** — automation / multi-site glue
- **Dashboard** — optional visibility without a full SOC UI

## Next (roadmap)

1. Alert rate-limit / dedupe
2. WhatsApp/Telegram digest push
3. Multi-tenant central dashboard
4. Windows agent packaging
5. Signed release artifacts
