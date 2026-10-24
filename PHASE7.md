# Phase 7 — Case & Triage Workflow

**Status:** Implemented (2026-10-24)  
**Repo:** https://github.com/trintechdigitaldefense/Sentinel

## Goals achieved

1. **Durable cases** (`modules/cases.py`)
   - SQLite store at `~/.sentinel/data/cases.db`
   - Fields: id, title, status, severity, assignee, source, source_event_id, summary, timestamps
   - Statuses: `new`, `triaging`, `investigating`, `contained`, `resolved`, `false_positive`

2. **Triage actions**
   - Create / list / get
   - Status change
   - Assignment
   - Notes
   - Attach alert references
   - Create from normalized connector alert

3. **Audit**
   - Every create, status change, assign, note, attach, and evidence export is recorded on the case

4. **Evidence pack**
   - Zip bundle: `case.json`, matched alerts, `MANIFEST.json` with per-file SHA-256
   - Sidecar `.zip.sha256` for the archive
   - Written under `~/.sentinel/data/evidence/`

5. **CLI** — `modules/cases_cli.py`
6. **Tests** — `tests/test_cases_phase7.py`

## Quick use

```bash
# Create
python3 -c "from modules.cases_cli import main; main(['create','--title','Canary hit','--severity','high'])"

# List open
python3 -c "from modules.cases_cli import main; main(['list','--status','new'])"

# Status + assign + note
python3 -c "from modules.cases_cli import main; main(['status','CASE-...','investigating'])"
python3 -c "from modules.cases_cli import main; main(['assign','CASE-...','jason'])"
python3 -c "from modules.cases_cli import main; main(['note','CASE-...','--body','Reviewing FIM events'])"

# Evidence pack
python3 -c "from modules.cases_cli import main; main(['evidence','CASE-...'])"
```

## Tests

```bash
pytest tests/test_cases_phase7.py -q
```

## Integration notes

- Connector alerts (Phase 6) can open cases via `create_from_normalized_alert()`.
- Central audit (Phase 5) remains separate; case audit is local to the operator host.
- Response actions stay human-gated (unchanged).

## Roadmap position

Phases 0–7 complete for the current product line. Deferred items (cloud SIEM replacement, autonomous response, AI summarization) remain out of scope unless re-opened deliberately.
