# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multiprocess tests for AlertEngine delivery deduplication."""
import multiprocessing
import json
import os


def _alert_worker(root, start_event, result_queue):
    os.environ["SENTINEL_DIR"] = root

    from modules.alerting import AlertEngine

    start_event.wait(10)
    result = AlertEngine({"dedup_minutes": 60}).send(
        "HIGH",
        "concurrent-alert-test",
        "same-fingerprint-details",
    )
    result_queue.put({
        "ok": result.get("ok"),
        "deduped": result.get("deduped"),
        "queued_offline": result.get("queued_offline", False),
    })


def test_concurrent_identical_alerts_are_queued_once(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start_event = ctx.Event()
    result_queue = ctx.Queue()

    workers = [
        ctx.Process(
            target=_alert_worker,
            args=(str(tmp_path), start_event, result_queue),
        )
        for _ in range(6)
    ]

    for worker in workers:
        worker.start()

    start_event.set()
    results = [result_queue.get(timeout=20) for _ in workers]

    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert all(result["ok"] for result in results)
    assert sum(result["queued_offline"] for result in results) == 1
    assert sum(result["deduped"] for result in results) == 5

    data_dir = tmp_path / "data"
    dedup_file = data_dir / "alert_dedup.json"
    dedup_lock = data_dir / "alert_dedup.json.lock"

    assert dedup_file.exists()
    assert dedup_file.stat().st_mode & 0o777 == 0o600
    assert dedup_lock.exists()
    assert dedup_lock.stat().st_mode & 0o777 == 0o600

    stored = json.loads(dedup_file.read_text())
    assert len(stored) == 1
