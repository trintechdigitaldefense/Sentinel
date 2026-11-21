from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cases_cli_list_runs_in_isolated_home(tmp_path):
    env = os.environ.copy()
    env["SENTINEL_DIR"] = str(tmp_path / "sentinel")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(ROOT / "sentinel.py"), "cases", "list"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No open cases." in result.stdout


def test_send_alert_auto_opens_case_hook(tmp_path, monkeypatch):
    import sentinel
    from modules import alerting, case_hooks, critical_alerts

    called = []
    order = []
    monkeypatch.setattr(
        sentinel,
        "load_config_safe",
        lambda: {
            "alerting": {"log_file": str(tmp_path / "alerts.jsonl")},
            "quarantine": {"on_alerts": []},
        },
    )
    monkeypatch.setattr(sentinel, "get_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(sentinel, "quiet_should_emit", lambda *args, **kwargs: True)
    monkeypatch.setattr(sentinel, "auto_quarantine", lambda *args, **kwargs: None)
    monkeypatch.setattr(sentinel, "CRITICAL_ALERTS", set())
    monkeypatch.setattr(
        case_hooks,
        "maybe_open_case_from_engine_alert",
        lambda alert_type, details, actor="sentinel": called.append((alert_type, details)),
    )
    monkeypatch.setattr(critical_alerts, "is_critical", lambda *args, **kwargs: True)
    monkeypatch.setattr(critical_alerts, "record", lambda *args, **kwargs: None)

    class FakeRouter:
        def __init__(self, config):
            pass

        def send(self, *args, **kwargs):
            order.append("router")
            return {"sent": True, "queued_offline": False, "suppressed": False, "deduped": False, "channels": ["test"]}

    monkeypatch.setattr(alerting, "AlertRouter", FakeRouter)
    result = sentinel.send_alert("CANARY_TRIGGERED", {"canary_id": "case-test-1"})

    assert result["ok"] is True
    assert called == [("CANARY_TRIGGERED", {"canary_id": "case-test-1"})]
    assert order == ["router", "case"]
    assert (tmp_path / "alerts.jsonl").exists()
