# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Enrich dashboard status with open cases (Phase 7).

Call enrich(out) from collect_full.
"""
from __future__ import annotations


def enrich(out: dict) -> dict:
    try:
        from modules.cases import list_cases
        open_statuses = ("new", "triaging", "investigating", "contained")
        open_cases = []
        for st in open_statuses:
            open_cases.extend(list_cases(status=st, limit=20))
        open_cases = sorted(open_cases, key=lambda c: c.get("updated_at") or "", reverse=True)[:30]
        out["cases_open"] = open_cases
        out["cases_open_count"] = len(open_cases)
    except Exception as e:
        out.setdefault("cases_open", [])
        out.setdefault("cases_open_count", 0)
        out["cases_error"] = str(e)
    return out
