# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.threat_intel import enrich_ip


def test_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = enrich_ip("1.1.1.1", {"enabled": False})
    assert r.get("skipped")


def test_no_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = enrich_ip("1.1.1.1", {"enabled": True})
    assert r.get("ok") is False or r.get("error")


def test_empty_ip(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = enrich_ip("", {"enabled": True, "abuseipdb_key": "x"})
    assert r.get("ok") is False
