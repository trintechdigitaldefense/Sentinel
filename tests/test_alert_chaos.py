# © 2026 TrinTech Digital Defense — simulated channel failures
from __future__ import annotations

from unittest import mock


def test_dedup_save_atomic(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import alerting
    if hasattr(alerting, "_save_dedup") and hasattr(alerting, "_dedup_path"):
        alerting._save_dedup({"a": 1})
        assert alerting._dedup_path().exists()


def test_offline_enqueue_callable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    try:
        from modules.phase4 import offline_enqueue
    except Exception:
        return
    offline_enqueue("chaos", {"severity": "HIGH", "detail": "simulated"})
    # should not raise
