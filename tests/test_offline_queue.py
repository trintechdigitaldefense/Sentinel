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



def test_enqueue_at_capacity_preserves_existing_unconfirmed_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    path = tmp_path / "data" / phase4.QUEUE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    original_rows = [
        json.dumps({"type": f"alert-{i}", "details": {"detail": str(i)}})
        for i in range(500)
    ]
    original_content = "\n".join(original_rows) + "\n"
    path.write_text(original_content, encoding="utf-8")

    result = phase4.offline_enqueue("new-alert", {"detail": "must not evict old alerts"})

    assert result["ok"] is False
    assert result["queued"] is False
    assert result["count"] == 500
    assert "full" in result["error"]
    assert path.read_text(encoding="utf-8") == original_content


def test_enqueue_accepts_last_slot_without_dropping_existing_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))

    path = tmp_path / "data" / phase4.QUEUE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    original_rows = [
        json.dumps({"type": f"alert-{i}", "details": {"detail": str(i)}})
        for i in range(499)
    ]
    path.write_text("\n".join(original_rows) + "\n", encoding="utf-8")

    result = phase4.offline_enqueue("last-slot", {"detail": "accepted"})

    assert result["ok"] is True
    assert result["queued"] == 500
    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 500
    assert json.loads(rows[-1])["type"] == "last-slot"
    assert json.loads(rows[0])["type"] == "alert-0"
