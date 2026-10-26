# SENTINEL testing notes

## Commands (reproducible)

```bash
# Compile all modules
python - <<'PY'
import py_compile
from pathlib import Path
for p in [Path("sentinel.py"), Path("setup.py"), *Path("modules").rglob("*.py")]:
    py_compile.compile(str(p), doraise=True)
print("compile OK")
PY

# Unit / integration tests
pytest -q tests/ --tb=line

# Installer shell syntax
bash -n install.sh

# Firewall dry-run smoke (no root required for dry paths)
python scripts/firewall_smoke.py
```

## Verified in Milestone 3–4 environment (2026-10-26)

Milestone 4 added self_defense / fim visibility / tripwire tests.

## Verified in Milestone 3 environment (2026-10-26)

| Check | Result |
|-------|--------|
| All `modules/**/*.py` compile | Pass (86 files) |
| `pytest -q tests/` | See CI / local run on hardening branch |
| `bash -n install.sh` | Pass |
| Future-import order guard | Pass |

## Known limitations

- Live firewall **apply** is not exercised in CI (requires disposable VM + root).
- Live SIEM/WhatsApp delivery is mocked or skipped.
- Dashboard browser XSS campaign not automated; authz unit tests cover control-mode escalation denial.
- Coverage % is not a security certification.

## CI

`.github/workflows/ci.yml` runs on `push` to `main` / `hardening/**` and PRs to `main`:
- ruff E9/F821/F823 on sentinel, setup, modules, tests
- compile all Python sources
- future-import guard
- firewall smoke
- full pytest
- `bash -n install.sh`
