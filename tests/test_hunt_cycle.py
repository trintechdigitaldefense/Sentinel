# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_run_cycle_minimal(env):
    from modules.hunt_cycle import run_cycle, load_metrics
    r = run_cycle({}, None, include_optional_hooks=False)
    assert "checks" in r
    assert "heartbeat" in r["checks"]
    m = load_metrics()
    assert m["cycles"] >= 1

def test_ops_collect(env):
    from modules.ops_status import collect
    d = collect()
    assert d["ok"]
    assert "hunt" in d
    assert "alerts" in d
