# SENTINEL testing notes

## Reproducible local checks

Run from the repository root in the intended Python environment:

```bash
# Compile all Python sources
python3 - <<'PY'
import py_compile
from pathlib import Path

for path in [Path("sentinel.py"), Path("setup.py"), *Path("modules").rglob("*.py")]:
    py_compile.compile(str(path), doraise=True)
print("compile OK")
PY

# Full automated test suite
python3 -m pytest -q

# Installer shell syntax
bash -n install.sh

# Firewall dry-run smoke (does not perform a live firewall apply)
python3 scripts/firewall_smoke.py
```

## Post-merge verification — PR #9

**Revision:** `e80c09b5a1cc461ed7d598cea9c1c5b2ec0c58ae`  
**Date:** 2026-11-17  
**Local runtime:** Python 3.12

| Check | Result |
|---|---|
| Local branch / revision | `main` at the same SHA as `origin/main` |
| `git diff --check` | Pass |
| `python3 -m pytest -q` | **242 passed**, 1 warning, 68.68 seconds |
| Warning | ReportLab emits a deprecation warning because it checks `ast.NameConstant`; no test failed |
| GitHub Actions for PR #9 | Python 3.10 and Python 3.12 jobs passed |

The local run above is the user's post-merge run, not a claim that every check in the reproducible command list was executed in that run. The PR's CI results are separate evidence.

## PR #9 regression coverage

The alert-reliability change adds or extends coverage for:

- Persistent active-finding lifecycle: new, unchanged, resolved, recurring, and changed fingerprints.
- Notification failure and retry behavior.
- Concurrent alert attempts and shared-state locking.
- Offline queue atomicity, retention of unconfirmed rows, and queued delivery retries.
- Email configuration compatibility and unified routing behavior.

Relevant files include `tests/test_alert_dedup.py`, `tests/test_alert_concurrency.py`, `tests/test_alert_engine_concurrency.py`, `tests/test_offline_queue.py`, `tests/test_queued_alert_delivery.py`, and `tests/test_alert_email_compat.py`.

## CI

The repository workflow runs lint/compile guards, the firewall smoke test, the full pytest suite, and installer shell syntax checks. For the authoritative status of a specific change, inspect that pull request's Actions checks.

## Checks that remain outside the automated suite

- Live firewall **apply** on a disposable VM with console recovery.
- Real email, WhatsApp, webhook, syslog, or Splunk delivery and receipt.
- Customer-host pilot/soak validation and restart/reboot behavior in the target environment.
- Full browser-based dashboard security/XSS testing.
- Detection quality and false-positive rate on representative customer workloads.

Passing unit tests and CI are useful evidence, not a security certification or a production-readiness declaration.
