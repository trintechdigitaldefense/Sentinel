# Changelog

## 3.3.0 — 2026-10-24

### Phase 9 — MSP daily use
- Open-cases digest (Telegram / WhatsApp): `modules/msp_digest.py`, bot `CASES`/`DIGEST`
- Client note templates: `modules/client_notes.py`, `cases client-note`
- Central read-only cases: `POST /v1/cases/sync`, `GET /v1/cases` via `scripts/apply_phase9_central.py`
- false_positive → suppression: `modules/case_suppress.py` + `modules/phase9_hooks.py`
- `scripts/phase9_smoke.py`, `PHASE9.md`

## 3.2.1 — 2026-10-24

### Phase 8 — Ship-ready wire
- Dashboard open-cases metric + table (`scripts/apply_dashboard_cases.py`)
- `scripts/phase8_smoke.py` acceptance smoke
- `docs/PHASE8_ACCEPTANCE.md` 10-minute checklist
- `PHASE8.md` + ROADMAP Phase 8 complete

## 3.2.0 — 2026-10-24

### Product line (Phases 0–7)
- Phase 0 discovery; Phase 5 central hardening; Phase 6 connectors; Phase 7 cases
- Cases integration: auto-open, dashboard enrich, apply_cases_wire

## 3.1.0 — 2026-10-15

Trust, MSP keys, backup/restore, Docker, CI.

## 3.0.0 — 2026-10-15

Plain source tree, config schema, multi-channel alerting, central server, Windows agent.
