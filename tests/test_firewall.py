# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path

def test_status_shape(env):
    from modules.firewall import status
    s = status()
    assert "backend" in s
    assert "note" in s

def test_block_dry_run(env):
    from modules.firewall import block_ip
    r = block_ip("203.0.113.50", confirm=False)
    assert r.get("dry_run") is True
    assert r.get("ok") is True

def test_invalid_ip(env):
    from modules.firewall import block_ip
    r = block_ip("127.0.0.1", confirm=True)
    assert r.get("ok") is False

def test_profiles(env):
    from modules.firewall import list_profiles, apply_profile
    p = list_profiles()
    assert "hardening" in p["profiles"]
    d = apply_profile("hardening", confirm=False)
    assert d.get("dry_run") is True

def test_managed_roundtrip(env):
    from modules.firewall import _load_blocks, _save_blocks, list_managed
    data = _load_blocks()
    data["ips"].append("198.51.100.9")
    _save_blocks(data)
    m = list_managed()
    assert "198.51.100.9" in m["ips"]

def test_doctor(env):
    from modules.firewall import doctor
    d = doctor()
    assert "backend" in d
