# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL Client Dashboard — local visual UI + API."""
from __future__ import annotations

from modules.dashboard_impl import (
    collect_full,
    ensure_token,
    start_dashboard,
    DEFAULT_PORT,
)

__all__ = ["collect_full", "ensure_token", "start_dashboard", "DEFAULT_PORT"]

if __name__ == "__main__":
    start_dashboard()
