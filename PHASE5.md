# SENTINEL Phase 5 — Ops layer

## Features

| Command | Purpose |
|---------|---------|
| `phase5` | Self-check |
| `autosubnet` | Detect local /24 → config |
| `heartbeat` | Write/read heartbeat.json |
| `digest` | Alert summary → digest_latest.json |
| `whatsapp-digest [--force]` | Send digest via CallMeBot WhatsApp |
| `hygiene [--reset]` | Dedupe / rate-limit status |
| `status-json` | Machine-readable status |
| `dashboard` | HTML status on port 8787 |

## Hunt integration

Each hunt cycle calls `heartbeat_from_hunt()` so heartbeat age stays fresh while continuous protection runs.

## Alert hygiene

`send_alert()` is gated by `hygiene_should_emit()` — same alert key suppressed for **15 minutes** by default (`phase5.hygiene.window_sec`).

## WhatsApp setup

1. Get CallMeBot API key for your number  
2. Edit `~/.sentinel/config.json`:

```json
"alerting": {
  "whatsapp": {
    "enabled": true,
    "phone": "18683620679",
    "apikey": "YOUR_KEY"
  }
}
```

3. Test: `python3 sentinel.py whatsapp-digest --force`

## Install

```bash
git pull origin main
python3 setup.py
python3 wire_phase5.py
python3 sentinel.py phase5
```
