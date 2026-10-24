# Cases integration status (2026-10-24)

## On main

| Component | Status |
|-----------|--------|
| `modules/cases.py` + CLI | ✅ Phase 7 |
| `modules/case_hooks.py` | ✅ Auto-open high/critical (engine + connector) |
| `tests/test_case_hooks.py` | ✅ |
| `modules/connectors/cli.py --auto-case` | ✅ |
| `modules/dashboard_enrich.py` | ✅ |
| `modules/wire_cases.py` | ✅ Helper for menu + send_alert wrap |
| `modules/dashboard.py` | ✅ Bootstraps impl + enriches open cases |

## Menu + send_alert in sentinel.py

The full `sentinel.py` patch (v3.2.0) adds:

- Menu items **16** (list open cases) and **17** (cases submenu)
- Command: `python3 sentinel.py cases list|create|status|...`
- `send_alert()` calls `maybe_open_case_from_engine_alert` for critical types

That full engine file is prepared; apply on a machine with git push access:

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
# copy patched sentinel.py from the Phase 7 wire workspace, or merge these hooks:
```

### Minimal send_alert hook (add after writing alerts.log)

```python
try:
    from modules.case_hooks import maybe_open_case_from_engine_alert
    maybe_open_case_from_engine_alert(alert_type, details if isinstance(details, dict) else {"raw": details})
except Exception:
    pass
```

### Minimal cases command

```python
elif command == "cases":
    from modules.wire_cases import cases_command
    cases_command(args)
```

### Menu entries

```python
("16", "Cases — list open", ("cases", "list")),
("17", "Cases — create / triage submenu", ("__cases__",)),
```

### Dashboard open cases

`collect_full()` now includes `cases_open` / `cases_open_count` via `dashboard_enrich`.
Refresh the local dashboard to see open cases in `/api/status`.

### Connector auto-case

```bash
python3 -c "from modules.connectors.cli import main; main(['fetch','--source','sentinel_local','--auto-case'])"
```
