#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL Client Dashboard — visibility + control with login + optional TLS.

Bootstraps dashboard_impl.py from the last known-good commit if missing,
then enriches status with open cases (Phase 7).
"""
from __future__ import annotations

import importlib.util
import urllib.request
from pathlib import Path

GOOD = (
    "https://raw.githubusercontent.com/trintechdigitaldefense/Sentinel/"
    "41c636831b439a058001a1c3830eb2f4550d4df4/modules/dashboard.py"
)
HERE = Path(__file__).resolve().parent


def _ensure_impl() -> Path:
    target = HERE / "dashboard_impl.py"
    if target.exists() and target.stat().st_size > 1000:
        return target
    data = urllib.request.urlopen(GOOD, timeout=30).read()
    target.write_bytes(data)
    return target


_ensure_impl()
_spec = importlib.util.spec_from_file_location("dashboard_impl", HERE / "dashboard_impl.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# Re-export public API from implementation
for _name in dir(_mod):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_mod, _name)


def collect_full():
    out = _mod.collect_full()
    try:
        from modules.dashboard_enrich import enrich

        enrich(out)
    except Exception as e:
        out.setdefault("cases_open", [])
        out.setdefault("cases_open_count", 0)
        out["cases_error"] = str(e)
    return out


if __name__ == "__main__":
    start_dashboard()
