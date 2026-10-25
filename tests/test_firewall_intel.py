# © 2026 TrinTech Digital Defense
from __future__ import annotations
import json
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_profiles_include_caribbean(env):
    from modules.firewall import PROFILES, list_profiles
    assert "caribbean_smb" in PROFILES
    assert "zero_trust_edge" in PROFILES
    assert "database_guard" in PROFILES
    r = list_profiles()
    assert r["ok"]

def test_defense_pack_dry_run(env):
    from modules.firewall import apply_defense_pack
    r = apply_defense_pack(confirm=False)
    assert r["dry_run"] is True
    assert "plan" in r

def test_high_risk_dry_run(env):
    from modules.firewall import deny_high_risk_ports, HIGH_RISK_PORTS
    assert len(HIGH_RISK_PORTS) >= 10
    r = deny_high_risk_ports(confirm=False)
    assert r["dry_run"] is True

def test_intel_empty(env):
    from modules.firewall_intel import analyze
    r = analyze()
    assert r["ok"] is True

def test_intel_scores(env):
    from modules.firewall_intel import analyze
    p = env / "data" / "alerts.log"
    rec = {"title": "IP_BLOCKED", "detail": "brute from 203.0.113.88 failures=12"}
    p.write_text(json.dumps(rec) + "\n" + json.dumps(rec) + "\n")
    r = analyze()
    assert "203.0.113.88" in r.get("scored", {})
