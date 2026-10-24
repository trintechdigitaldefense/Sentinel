# Phase 8 — Ship-ready wire

**TrinTech Digital Defense · Sentinel 3.2.1**  
Status: implemented 2026-10-24

## Goal

Make the Phase 5–7 stack **field-ready**: every install gets the same operator path
(case menu, auto-open, dashboard open cases, acceptance smoke).

## Delivered

1. **Dashboard open cases**
   - Metric card + table (id, status, severity, title, assignee)
   - Fed by `cases_open` / `cases_open_count` from `dashboard_enrich`

2. **Acceptance smoke**
   - `python3 scripts/phase8_smoke.py`
   - Creates a case from a synthetic critical alert, lists open cases,
     exports evidence, checks dashboard status shape

3. **Install path**
   - `setup.py` / `install.sh` continue to run `scripts/apply_cases_wire.py`
   - Wire adds menu 16/17, `cases` command, `send_alert` → auto-case

4. **Docs**
   - This file + `docs/PHASE8_ACCEPTANCE.md`

## Out of scope (still deferred)

- Full SIEM replacement, autonomous response, AI core, multi-vendor correlation

## Acceptance (10 minutes)

See [docs/PHASE8_ACCEPTANCE.md](docs/PHASE8_ACCEPTANCE.md).

```bash
git pull
python3 setup.py
python3 scripts/phase8_smoke.py
python3 sentinel.py cases list
python3 sentinel.py dash   # open cases section on UI
```
