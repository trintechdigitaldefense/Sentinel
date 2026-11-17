# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multiprocess tests for finding notification serialization."""
import multiprocessing
import os
import time


def _finding_state_worker(root, start_event, result_queue):
    os.environ["SENTINEL_DIR"] = root
    from modules.finding_state import locked, pending_active, mark_handled

    start_event.wait(10)
    findings = {"same-finding": "same-fingerprint"}

    with locked("concurrency"):
        pending = pending_active("concurrency", findings)
        time.sleep(0.05)
        mark_handled("concurrency", findings, pending)

    result_queue.put(bool(pending))


def test_concurrent_finding_workflows_only_report_once(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start_event = ctx.Event()
    result_queue = ctx.Queue()

    workers = [
        ctx.Process(
            target=_finding_state_worker,
            args=(str(tmp_path), start_event, result_queue),
        )
        for _ in range(6)
    ]

    for worker in workers:
        worker.start()

    start_event.set()
    results = [result_queue.get(timeout=10) for _ in workers]

    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0

    assert sum(results) == 1

    lock_file = tmp_path / "data" / "finding_state_concurrency.json.lock"
    assert lock_file.exists()
    assert lock_file.stat().st_mode & 0o777 == 0o600
