# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 8 smoke components."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_enrich_adds_cases(env):
    from modules import cases
    from modules.dashboard_enrich import enrich

    cases.init_db()
    cases.create_case(title="p8", severity="high", source="test")
    out = {}
    enrich(out)
    assert out.get("cases_open_count", 0) >= 1
    assert out.get("cases_open")


def test_smoke_script_exists():
    root = Path(__file__).resolve().parents[1]
    assert (root / "scripts" / "phase8_smoke.py").exists()
