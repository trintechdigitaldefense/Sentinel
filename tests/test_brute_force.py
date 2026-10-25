# © 2026 TrinTech Digital Defense
from __future__ import annotations
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path

def test_parse_failures_ipv4(env):
    from modules.brute_force import parse_failures
    text = """
Failed password for root from 203.0.113.10 port 22 ssh2
Failed password for root from 203.0.113.10 port 22 ssh2
Failed password for admin from 198.51.100.20 port 22 ssh2
Invalid user ubuntu from 203.0.113.10
"""
    f = parse_failures(text)
    assert f["203.0.113.10"] >= 3
    assert f["198.51.100.20"] == 1

def test_parse_rhost(env):
    from modules.brute_force import parse_failures
    text = "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.55"
    f = parse_failures(text)
    assert "192.0.2.55" in f

def test_check_no_crash(env):
    from modules.brute_force import check, status
    r = check(config={"ssh_blocking": {"active": True, "max_failures": 99, "auto_block": False}})
    assert r["ok"] is True
    assert status()["ok"] is True

def test_whitelist(env):
    from modules.brute_force import whitelist_add, status
    whitelist_add("203.0.113.9")
    assert "203.0.113.9" in status()["whitelist"]
