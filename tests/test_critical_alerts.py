# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_record_and_ack(env):
    from modules.critical_alerts import record, list_open, ack, status
    r = record("REVERSE_SHELL", {"pid": "1"}, host="h")
    assert r["ok"] and r.get("created")
    open_items = list_open()
    assert len(open_items) == 1
    aid = open_items[0]["id"]
    # duplicate bumps count
    r2 = record("REVERSE_SHELL", {"pid": "1"}, host="h")
    assert r2.get("count") == 2
    a = ack(aid)
    assert a["ok"]
    assert status()["open_count"] == 0

def test_non_critical_skipped(env):
    from modules.critical_alerts import record
    r = record("INFO_NOTE", {})
    assert r.get("skipped")
