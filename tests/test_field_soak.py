# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_field_soak_no_confirm(env):
    from modules.field_soak import run_field_soak
    r = run_field_soak(confirm=False, run_sim=True)
    assert "steps" in r
    assert r.get("report_path")
    names = [s["step"] for s in r["steps"]]
    assert "preflight" in names
    assert "alert_channels" in names
