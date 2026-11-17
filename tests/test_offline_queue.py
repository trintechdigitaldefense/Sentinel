import json

from modules import phase4


def test_flush_without_sender_preserves_queue(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    phase4.offline_enqueue("first", {"detail": "keep me"})
    path = tmp_path / "data" / phase4.QUEUE_FILE
    before = path.read_text()

    result = phase4.offline_flush()

    assert result["ok"] is False
    assert result["flushed"] == 0
    assert result["retained"] == 1
    assert path.read_text() == before


def test_flush_removes_only_confirmed_deliveries(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    phase4.offline_enqueue("delivered", {"detail": "first"})
    phase4.offline_enqueue("failed", {"detail": "second"})

    def sender(alert_type, details):
        if alert_type == "delivered":
            return {"sent": True}
        return {"ok": False}

    result = phase4.offline_flush(sender)

    assert result == {
        "ok": False,
        "flushed": 1,
        "errors": 1,
        "retained": 1,
    }

    remaining = phase4.offline_status()
    assert remaining["count"] == 1
    assert remaining["items"][0]["type"] == "failed"


def test_flush_retains_exceptions_and_unconfirmed_results(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    phase4.offline_enqueue("exception", {"detail": "first"})
    phase4.offline_enqueue("unconfirmed", {"detail": "second"})

    def sender(alert_type, details):
        if alert_type == "exception":
            raise RuntimeError("simulated delivery failure")
        return {"ok": True, "sent": False}

    result = phase4.offline_flush(sender)

    assert result["flushed"] == 0
    assert result["errors"] == 2
    assert result["retained"] == 2
    assert phase4.offline_status()["count"] == 2


def test_flush_retains_malformed_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    path = tmp_path / "data" / phase4.QUEUE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{malformed queue entry}\n")

    result = phase4.offline_flush(lambda *args: True)

    assert result["flushed"] == 0
    assert result["errors"] == 1
    assert result["retained"] == 1
    assert path.read_text() == "{malformed queue entry}\n"


def test_flush_preserves_entries_added_during_delivery(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    phase4.offline_enqueue("original", {"detail": "first"})

    def sender(alert_type, details):
        phase4.offline_enqueue(
            "added-during-flush", {"detail": "new entry"}
        )
        return {"sent": True}

    result = phase4.offline_flush(sender)

    assert result["flushed"] == 1
    assert result["errors"] == 0
    assert result["retained"] == 1

    remaining = phase4.offline_status()
    assert remaining["count"] == 1
    assert remaining["items"][0]["type"] == "added-during-flush"
