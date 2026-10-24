# Phase 9 — MSP daily use

**TrinTech Digital Defense · Sentinel 3.3.0**  
Status: implemented 2026-10-24

## Goal

Make cases usable every day for MSP operators without a full SIEM console.

## Delivered

1. **Open-cases digest** (`modules/msp_digest.py`)
   - Text digest of open cases
   - Send via Telegram bot and/or WhatsApp (CallMeBot config)
   - Bot commands: `CASES`, `DIGEST`
   - CLI: `sentinel cases digest` / `digest-send`

2. **Client note templates** (`modules/client_notes.py`)
   - Plain-language note for SMB owners
   - Saved under `~/.sentinel/data/client_notes/` and as a case note
   - CLI: `sentinel cases note <CASE_ID> [ClientName]`

3. **Central read-only case list**
   - Agent: `POST /v1/cases/sync` with open case summaries
   - Master: `GET /v1/cases?client_id=`
   - Helper: `modules/cases_sync.py` / `sentinel cases sync`

4. **False-positive → suppression**
   - `set_status(..., false_positive)` creates a linked suppression rule
   - `modules/case_suppress.py`

## Smoke

```bash
python3 scripts/phase9_smoke.py
```

## Deferred (still)

Full SIEM, autonomous response, AI core, multi-vendor correlation.
