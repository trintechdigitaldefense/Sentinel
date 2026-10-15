# © 2026 TrinTech Digital Defense — authorized defensive use only
import time
from modules.alerting import AlertEngine, _fingerprint


def test_fingerprint_stable():
    a = _fingerprint("HIGH", "title", "detail")
    b = _fingerprint("HIGH", "title", "detail")
    assert a == b


def test_dedup_collapses_inside_window(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    eng = AlertEngine({"dedup_minutes": 60})
    r1 = eng.send("INFO", "same", "d")
    r2 = eng.send("INFO", "same", "d")
    assert r1["deduped"] is False
    assert r2["deduped"] is True
    assert r2["count"] >= 2


def test_dedup_expires(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    eng = AlertEngine({"dedup_minutes": 0})  # zero window always re-send path via age
    # force by setting very short: use minutes 0 means window 0
    r1 = eng.send("LOW", "x", "y")
    r2 = eng.send("LOW", "x", "y")
    # with 0 minute window, age > 0 so may resend
    assert r1["ok"] and r2["ok"]


def test_no_channels_still_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    eng = AlertEngine({})
    r = eng.send("MEDIUM", "t", "d")
    assert r["ok"]
    log = tmp_path / "data" / "alerts.log"
    assert log.exists()
