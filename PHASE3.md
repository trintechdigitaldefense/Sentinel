# Phase 3 — Operator’s Brain

**Goal:** Sentinel becomes the control plane for TrinTech managed service.

## WhatsApp (default)

**Report / alert number:** `+1 868 362-0679` (Trinidad & Tobago)

```json
"alerting": {
  "whatsapp": {
    "enabled": true,
    "phone": "18683620679",
    "provider": "callmebot",
    "apikey": ""
  }
}
```

### One-time CallMeBot setup

1. Save **+34 644 59 71 67** in WhatsApp contacts (CallMeBot)
2. Send: `I allow callmebot to send me messages`
3. Bot replies with your **apikey**
4. Put it in `~/.sentinel/config.json` → `alerting.whatsapp.apikey`

## Features

| # | Feature |
|---|--------|
| 11 | Lightweight dashboard (port 8787) |
| 12 | Multi-tenant registry |
| 13 | WhatsApp alert routing (default TT number) |
| 14 | Weekly auto-report → WhatsApp |
| 15 | Health / heartbeat |

## Install / wire

```bash
git pull
python3 restore_phase3.py
python3 wire_phase3.py
python3 sentinel.py phase3
python3 sentinel.py whatsapp-test
python3 sentinel.py dashboard
python3 sentinel.py weekly-report
```

## CLI

| Command | Purpose |
|---------|--------|
| `sentinel dashboard` | Status web UI :8787 |
| `sentinel whatsapp-test` | Test message to +1-868-362-0679 |
| `sentinel weekly-report` | Weekly summary (+ WhatsApp) |
| `sentinel health` | Self health check |
| `sentinel tenants` | List clients |
| `sentinel tenants add NAME` | Register tenant |
| `sentinel phase3` | Phase 3 self-check |
