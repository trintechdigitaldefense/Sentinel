# SENTINEL Phase 6 — Always-on + scheduled digests

## Commands

| Command | Purpose |
|---------|---------|
| `service-install` | Enable systemd unit running `hunt` (always-on) |
| `service-status` | Show unit status |
| `service-stop` | Stop and disable unit |
| `digest-cron` | Daily WhatsApp digest at 08:00 (`--weekly` / `--remove`) |
| `phase6` | Self-check |

## Menu (after wire)

- **13** Always-on service  
- **14** Service status  
- **15** Schedule WhatsApp digest  

## Also enforced by wire_phase6

- Hunt loop → `heartbeat_from_hunt()` every cycle  
- `send_alert()` → hygiene gate  

## Client runbook

See **Sentinel_Client_Runbook.pdf** (authorize → install → baseline → always-on).

```bash
git pull origin main
python3 setup.py
python3 wire_phase6.py
python3 sentinel.py service-install
python3 sentinel.py service-status
```
