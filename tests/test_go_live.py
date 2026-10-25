# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_go_live_alert_channel(env):
    from modules.go_live import ensure_alert_channel, _load_cfg
    r = ensure_alert_channel({})
    assert r["ok"] and r["local_ship"]
    cfg = _load_cfg()
    assert cfg["alerting"]["siem"]["enabled"] is True

def test_go_live_runs(env):
    from modules.go_live import run_go_live
    r = run_go_live(config={}, logger=None)
    assert "steps" in r
    names = [s["step"] for s in r["steps"]]
    assert "alert_channel" in names
    assert "directories" in names
