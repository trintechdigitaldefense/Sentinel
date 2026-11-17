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
    from modules.alerting import AlertEngine, _fingerprint, _save_dedup

    eng = AlertEngine({"dedup_minutes": 0})
    assert eng.dedup_minutes == 0

    fp = _fingerprint("LOW", "x", "y")
    _save_dedup({fp: {"ts": 1000.0, "count": 1}})

    monkeypatch.setattr("modules.alerting.time.time", lambda: 1001.0)

    assert eng.should_send(fp) == (True, 1)


def test_no_channels_still_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    eng = AlertEngine({})
    r = eng.send("MEDIUM", "t", "d")
    assert r["ok"]
    log = tmp_path / "data" / "alerts.log"
    assert log.exists()


def test_failed_offline_queue_is_retryable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import phase4
    from modules.alerting import AlertEngine

    attempts = []

    def failed_queue(*args, **kwargs):
        attempts.append(args)
        return {"ok": False}

    monkeypatch.setattr(phase4, "offline_enqueue", failed_queue)
    engine = AlertEngine({"dedup_minutes": 60})

    first = engine.send("HIGH", "retry-me", "delivery failure")
    second = engine.send("HIGH", "retry-me", "delivery failure")

    assert first["ok"] is False
    assert first["queued_offline"] is False
    assert second["deduped"] is False
    assert len(attempts) == 2


def test_successful_offline_queue_is_deduplicated(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import phase4
    from modules.alerting import AlertEngine

    attempts = []

    def successful_queue(*args, **kwargs):
        attempts.append(args)
        return {"ok": True}

    monkeypatch.setattr(phase4, "offline_enqueue", successful_queue)
    engine = AlertEngine({"dedup_minutes": 60})

    first = engine.send("HIGH", "queue-me", "queued successfully")
    second = engine.send("HIGH", "queue-me", "queued successfully")

    assert first["queued_offline"] is True
    assert first["ok"] is True
    assert second["deduped"] is True
    assert len(attempts) == 1


def test_alert_router_compatibility(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    from modules import phase4
    from modules.alerting import AlertEngine, AlertRouter

    monkeypatch.setattr(
        phase4,
        "offline_enqueue",
        lambda *args, **kwargs: {"ok": True},
    )

    assert AlertRouter is AlertEngine
    result = AlertRouter({}).send("INFO", "compatibility", "test")
    assert result["ok"] is True


def test_sentinel_send_alert_without_delivery_remains_unhandled(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    import sentinel
    from modules import alerting

    monkeypatch.setattr(sentinel, "load_config_safe", lambda: {
        "alerting": {},
        "quarantine": {},
    })

    monkeypatch.setattr(
        sentinel,
        "quiet_should_emit",
        lambda *args, **kwargs: True,
    )

    monkeypatch.setattr(
        alerting.AlertRouter,
        "send",
        lambda *args, **kwargs: {
            "ok": True,  # Simulates local logging only.
            "sent": False,
            "queued_offline": False,
            "suppressed": False,
            "deduped": False,
            "channels": [],
        },
    )

    result = sentinel.send_alert(
        "TEST_DELIVERY_UNAVAILABLE",
        {"detail": "no delivery channels"},
    )

    assert result["sent"] is False
    assert result["queued_offline"] is False
    assert result["suppressed"] is False
    assert result["deduped"] is False
    assert result["ok"] is False
