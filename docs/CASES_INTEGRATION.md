# Cases integration status (2026-11-21)

## Current main-branch integration

| Component | Status |
|---|---|
| `modules/cases.py` and case storage | Implemented |
| `modules/case_hooks.py` | Auto-opens cases for configured high-signal engine alerts; deduplicates by source event |
| `modules/wire_cases.py` | Provides the cases subcommand handler |
| `sentinel.py send_alert()` | Calls the case auto-open hook after alert logging and critical persistence |
| `sentinel.py cases ...` | CLI dispatches to `modules.wire_cases.cases_command` |
| `tests/test_case_hooks.py` | Covers engine/normalized alert case creation and deduplication |
| Dashboard API | `collect_full()` includes `cases_open` and `cases_open_count`; this is API data, not a rendered dashboard panel |

## Operator commands

```bash
python3 sentinel.py cases list
python3 sentinel.py cases list-all
python3 sentinel.py cases create "Investigate suspicious activity"
python3 sentinel.py cases get <CASE_ID>
python3 sentinel.py cases status <CASE_ID> investigating
python3 sentinel.py cases assign <CASE_ID> "Operator"
python3 sentinel.py cases note <CASE_ID> "Investigation update"
python3 sentinel.py cases evidence <CASE_ID>
```

The standalone module CLI remains available:

```bash
python3 -m modules.cases_cli list
```

## Dashboard boundary

The active dashboard API exposes open-case counts/data, but the legacy `scripts/apply_dashboard_cases.py` injection is not part of the tracked UI. That script currently renders case values with unsafe `innerHTML` and must not be run or used as a release step. A dashboard panel should be implemented directly in the active dashboard template using DOM construction and `textContent`, with browser tests for hostile values.

## Setup boundary

The current setup path still invokes legacy source-wiring scripts. The case CLI and alert hook are now tracked in `sentinel.py`; a separate setup-safety change must remove the redundant runtime source-rewriting calls only after the dashboard injection is removed from the setup path. Do not treat setup as non-mutating until that follow-up is merged and verified.
