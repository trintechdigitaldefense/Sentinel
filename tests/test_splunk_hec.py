# © 2026 TrinTech Digital Defense
from __future__ import annotations
import json
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    return tmp_path

def test_normalize_url(env):
    from modules.siem import normalize_hec_url
    assert normalize_hec_url("https://splunk:8088").endswith("/services/collector")
    assert "/services/collector" in normalize_hec_url("https://splunk:8088/services/collector")

def test_configure_splunk(env):
    from modules.siem import configure_splunk, status
    r = configure_splunk("https://splunk.example:8088", "tok-test", index="security")
    assert r["ok"]
    st = status()
    assert st["enabled"] is True
    assert st["splunk_hec"] is True
    cfg = json.loads((env / "config.json").read_text())
    assert cfg["alerting"]["siem"]["splunk_hec"]["token"] == "tok-test"
    assert cfg["alerting"]["siem"]["splunk_hec"]["index"] == "security"
