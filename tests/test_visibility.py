# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_inventory_processes(env):
    from modules.visibility import inventory_processes
    r = inventory_processes()
    assert r["ok"]
    assert r["total"] >= 1

def test_inventory_devices(env):
    from modules.visibility import inventory_devices
    r = inventory_devices()
    assert r["ok"] is True
    assert "count" in r

def test_full_inventory(env):
    from modules.visibility import full_inventory
    r = full_inventory()
    assert r["ok"]
    assert "processes" in r
    assert "devices" in r
