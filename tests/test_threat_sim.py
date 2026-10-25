# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path

def test_list_scenarios(env):
    from modules.threat_sim import list_scenarios
    r = list_scenarios()
    assert r["ok"]
    assert "canary" in r["scenarios"]

def test_refuses_without_confirm(env):
    from modules.threat_sim import run
    r = run(["canary"], confirm=False)
    assert r["ok"] is False

def test_behavioral_and_cleanup(env):
    from modules.threat_sim import run, cleanup
    r = run(["behavioral"], confirm=True)
    assert r["ok"] is True
    c = cleanup()
    assert c["ok"] is True

def test_fim_sim(env):
    from modules.threat_sim import run
    r = run(["fim"], confirm=True)
    assert r["ok"] is True
    assert r["results"][0]["scenario"] == "fim"
