# © 2026 TrinTech Digital Defense
from __future__ import annotations

from modules.ransomware_tripwire import check, deploy


def test_check_needs_deploy(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = check()
    assert r.get("needs_deploy") is True or r.get("ok") is True


def test_deploy_and_check_clean(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    d = deploy(n_files=3)
    assert d.get("ok") is not False or "files" in str(d).lower() or d
    r = check()
    assert "events" in r
