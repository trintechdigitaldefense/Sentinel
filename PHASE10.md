# Phase 10 — Operational cadence

**TrinTech Digital Defense · Sentinel 3.4.0**  
Status: implemented 2026-10-24

## Goal

Turn Phase 9 MSP features into **repeatable daily operations**: scheduled digests,
connector enablement, and master-side case listing.

## Delivered

1. **Digest cron** (`modules/digest_cron.py`)
   - `run_digest_job()` — send + save `~/.sentinel/data/last_digest.txt`
   - `install()` — systemd user timer **or** user crontab (08:00 default)

2. **Connector enablement** (`modules/connector_enable.py`)
   - `enable_wazuh(url, user, password)` — read-only creds in config
   - `enable_local(auto_case=True)` / `fetch_and_maybe_case(source)`

3. **Central cases CLI** (`modules/central_cases_cli.py`)
   - Master-key `GET /v1/cases`

4. **Smoke** — `python3 scripts/phase10_smoke.py`

## Quick start

```bash
git pull
python3 scripts/phase10_smoke.py
python3 -c "from modules.digest_cron import install; print(install(hour=8))"
python3 -c "from modules.connector_enable import enable_local; print(enable_local())"
```

## Deferred

Full SIEM, autonomous response, AI core, multi-vendor correlation.
