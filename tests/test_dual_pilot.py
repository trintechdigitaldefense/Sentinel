# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Dual-connector pilot tests."""
from __future__ import annotations

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_correlation_uses_asset_id_and_occurred_at(env):
    from modules.correlation import correlate

    alerts = [
        {
            "source": "sentinel_local",
            "asset_id": "desk-1",
            "title": "canary",
            "severity": "critical",
            "occurred_at": "2026-10-24T12:00:00+00:00",
        },
        {
            "source": "wazuh",
            "asset_id": "desk-1",
            "title": "auth",
            "severity": "high",
            "occurred_at": "2026-10-24T12:10:00+00:00",
        },
    ]
    b = correlate(alerts, window_minutes=45, min_sources=2)
    assert b
    assert b[0]["host"] == "desk-1"


def test_dual_pilot_lab_mode(env):
    from modules.dual_pilot import ensure_pilot_config, run_pilot

    ensure_pilot_config(window_minutes=45, lab_mode=True)
    r = run_pilot(promote=True, lab_mode=True, inject_lab_alerts=True)
    assert r["ok"]
    assert r["used_lab_alerts"] is True
    assert r["bundle_count"] >= 1
    assert r["promoted_cases"]
