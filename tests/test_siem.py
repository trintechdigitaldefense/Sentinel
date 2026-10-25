# © 2026 TrinTech Digital Defense
from __future__ import annotations
import json
import pytest

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir(parents=True)
    cfg = {
        "alerting": {
            "siem": {
                "enabled": True,
                "format": "json",
                "min_severity": "LOW",
                "ship_file": {"enabled": True},
                "syslog": {"enabled": False},
            }
        }
    }
    (tmp_path / "config.json").write_text(json.dumps(cfg))
    return tmp_path

def test_cef_format(env):
    from modules.siem import to_cef
    s = to_cef("HIGH", "REVERSE_SHELL", "pid=1", {"type": "REVERSE_SHELL"})
    assert s.startswith("CEF:0|TrinTech|Sentinel|")
    assert "REVERSE_SHELL" in s

def test_emit_ship_file(env):
    from modules.siem import emit, status
    r = emit("HIGH", "TEST_ALERT", "detail", meta={"type": "TEST"}, cfg={
        "enabled": True,
        "ship_file": {"enabled": True},
        "syslog": {"enabled": False},
    })
    assert r.get("sent")
    st = status()
    assert st["ship_file_lines"] >= 1

def test_disabled(env):
    from modules.siem import emit
    r = emit("HIGH", "X", cfg={"enabled": False})
    assert r.get("skipped")
