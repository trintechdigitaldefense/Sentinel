#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL Client Dashboard — visibility + control with login + optional TLS."""
from __future__ import annotations

# Re-export implementation
from modules.dashboard_impl import *  # noqa: F401,F403
from modules.dashboard_impl import collect_full as _collect_full_impl
from modules.dashboard_impl import start_dashboard, ensure_token, run_action, html_page, login_page


def collect_full():
    out = _collect_full_impl()
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
