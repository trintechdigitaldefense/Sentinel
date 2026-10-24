# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path

def test_status_version(env):
    from modules.firewall import status, VERSION
    s = status()
    assert s.get("version") == VERSION
    assert "backend" in s

def test_block_dry_run(env):
    from modules.firewall import block_ip
    r = block_ip("203.0.113.50", confirm=False)
    assert r.get("dry_run") is True
    assert r.get("ok") is True

def test_block_cidr_dry_run(env):
    from modules.firewall import block_ip
    r = block_ip("203.0.113.0/24", confirm=False)
    assert r.get("dry_run") is True
    assert r.get("kind") == "cidr"

def test_refuse_localhost(env):
    from modules.firewall import block_ip
    assert block_ip("127.0.0.1", confirm=True).get("ok") is False
    assert block_ip("0.0.0.0/0", confirm=True).get("ok") is False

def test_profiles_lab(env):
    from modules.firewall import list_profiles, apply_profile
    assert "lab_lockdown" in list_profiles()["profiles"]
    assert apply_profile("lab_lockdown", confirm=False).get("dry_run") is True

def test_apply_managed_dry(env):
    from modules.firewall import apply_managed, _load_blocks, _save_blocks
    data = _load_blocks()
    data["ips"].append("198.51.100.8")
    _save_blocks(data)
    r = apply_managed(confirm=False)
    assert "198.51.100.8" in r.get("would_apply_ips", [])

def test_enable_disable(env):
    from modules.firewall import set_enabled, list_managed
    set_enabled(False)
    assert list_managed().get("enabled") is False
    set_enabled(True)

def test_doctor(env):
    from modules.firewall import doctor
    d = doctor()
    assert "version" in d
