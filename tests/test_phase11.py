# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 11 tests."""
from __future__ import annotations

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_correlate_multi_source(env):
    from modules.correlation import correlate

    alerts = [
        {
            "source": "a",
            "host": "h1",
            "title": "x",
            "severity": "HIGH",
            "observed_at": "2026-10-24T10:00:00+00:00",
        },
        {
            "source": "b",
            "host": "h1",
            "title": "y",
            "severity": "LOW",
            "observed_at": "2026-10-24T10:10:00+00:00",
        },
    ]
    b = correlate(alerts, min_sources=2)
    assert b and b[0]["host"] == "h1"
    assert "a" in b[0]["sources"] and "b" in b[0]["sources"]


def test_gated_no_auto_execute(env):
    from modules.gated_response import execute_recommendation

    r = execute_recommendation("block_ip", "10.0.0.1", confirm=False)
    assert r["ok"] is False


def test_ai_offline(env):
    from modules.ai_assist import offline_summary

    t = offline_summary({"id": "CASE-1", "title": "test", "status": "new", "severity": "high"})
    assert "CASE-1" in t
