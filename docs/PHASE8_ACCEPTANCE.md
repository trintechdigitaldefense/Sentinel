# Phase 8 acceptance checklist

**Target:** ~10 minutes on a lab host after install.

## 1. Install / wire

```bash
cd /path/to/Sentinel
git pull
python3 setup.py
```

Expect: engine compiles; cases wire applied (or already present).

## 2. Automated smoke

```bash
python3 scripts/phase8_smoke.py
```

Expect: exit 0; case created, listed, evidence exported; status has `cases_open`.

## 3. Manual critical path

```bash
python3 -c "
from modules.case_hooks import maybe_open_case_from_engine_alert
print(maybe_open_case_from_engine_alert('CANARY_TRIGGERED', {'path': '/tmp/p8-canary', 'canary_id': 'p8'}))
"

python3 sentinel.py cases list
python3 -c "from modules.connectors.cli import main; main(['fetch','--source','sentinel_local','--limit','5','--auto-case'])"
```

## 4. Dashboard

```bash
python3 sentinel.py dash
# Browser: http://127.0.0.1:8792 — Open cases metric + table
```

## 5. Sign-off

| Check | Pass |
|-------|------|
| setup.py OK | ☐ |
| phase8_smoke.py exit 0 | ☐ |
| cases list shows open case | ☐ |
| evidence zip under ~/.sentinel/data/evidence | ☐ |
| dashboard shows open cases | ☐ |

Client pilot may stop here; real connector credentials are optional next step.
