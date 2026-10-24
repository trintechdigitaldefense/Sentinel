# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Tests for case auto-open hooks."""
from __future__ import annotations

import pytest

from modules.case_hooks import maybe_open_case_from_engine_alert, maybe_open_case_from_normalized
from modules import cases


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    cases.init_db()
    return tmp_path


def test_auto_open_canary(env):
    r = maybe_open_case_from_engine_alert("CANARY_TRIGGERED", {"path": "/tmp/secret.txt", "canary_id": "c1"})
    assert r is not None and r["ok"]
    cid = r["case"]["id"]
    # dedup
    r2 = maybe_open_case_from_engine_alert("CANARY_TRIGGERED", {"path": "/tmp/secret.txt", "canary_id": "c1"})
    assert r2 is None
    got = cases.get_case(cid)
    assert got["severity"] in ("high", "critical")


def test_skip_low_noise(env):
    assert maybe_open_case_from_engine_alert("NEW_DEVICE", {"ip": "1.2.3.4"}) is None


def test_normalized_high(env):
    r = maybe_open_case_from_normalized({
        "id": "x1", "source": "sentinel_local", "source_event_id": "e1",
        "severity": "critical", "title": "Shell", "detail": "bash -i",
    })
    assert r and r["ok"]
    assert maybe_open_case_from_normalized({
        "id": "x1", "source": "sentinel_local", "source_event_id": "e1",
        "severity": "critical", "title": "Shell",
    }) is None
