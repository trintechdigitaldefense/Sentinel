# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Regression tests for active-finding alert deduplication."""
from __future__ import annotations

import json
import logging

import pytest


@pytest.fixture
def sentinel_data(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    return tmp_path / "data"


def test_persistence_change_alerts_once_until_resolved(sentinel_data, monkeypatch):
    from modules import persistence_hunt

    path = "/tmp/sentinel-test-profile"
    baseline_meta = {"sha256": "baseline-hash", "type": "rc"}
    changed_meta = {"sha256": "changed-hash", "type": "rc"}
    current = {path: changed_meta}
    baseline = {"created": "test", "count": 1, "entries": {path: baseline_meta}}
    persistence_hunt.baseline_path().write_text(json.dumps(baseline))
    monkeypatch.setattr(persistence_hunt, "snapshot", lambda: dict(current))

    alerts = []
    send_alert = lambda alert_type, details: alerts.append((alert_type, details))
    first = persistence_hunt.check(send_alert=send_alert)
    assert [event["type"] for event in first["events"]] == ["RC_FILE_CHANGED"]
    assert len(alerts) == 1

    second = persistence_hunt.check(send_alert=send_alert)
    assert second["events"] == []
    assert len(alerts) == 1

    current[path] = baseline_meta
    assert persistence_hunt.check(send_alert=send_alert)["events"] == []

    current[path] = changed_meta
    again = persistence_hunt.check(send_alert=send_alert)
    assert [event["type"] for event in again["events"]] == ["RC_FILE_CHANGED"]
    assert len(alerts) == 2


def test_persistence_changed_fingerprint_alerts_again(sentinel_data, monkeypatch):
    from modules import persistence_hunt

    path = "/tmp/sentinel-test-profile"
    baseline = {"created": "test", "count": 1, "entries": {
        path: {"sha256": "baseline-hash", "type": "rc"}
    }}
    persistence_hunt.baseline_path().write_text(json.dumps(baseline))
    current = {path: {"sha256": "first-change", "type": "rc"}}
    monkeypatch.setattr(persistence_hunt, "snapshot", lambda: dict(current))
    alerts = []
    send_alert = lambda alert_type, details: alerts.append((alert_type, details))

    assert persistence_hunt.check(send_alert=send_alert)["count"] == 1
    current[path] = {"sha256": "second-change", "type": "rc"}
    assert persistence_hunt.check(send_alert=send_alert)["count"] == 1
    assert len(alerts) == 2


def test_cron_change_alerts_once_until_resolved(sentinel_data, monkeypatch):
    import sentinel as sentinel_module

    baseline_path = sentinel_data / "cron_baseline.json"
    baseline_path.write_text(json.dumps([
        {"source": "root_crontab", "entry": "trusted-entry"}
    ]))
    monkeypatch.setattr(sentinel_module, "CRON_BASELINE", baseline_path)
    current = {"text": "trusted-entry\nnew-digest-entry\n"}
    monkeypatch.setattr(sentinel_module, "run_cmd", lambda *a, **k: current["text"])

    real_exists = sentinel_module.os.path.exists
    monkeypatch.setattr(
        sentinel_module.os.path, "exists",
        lambda path: False if path == "/etc/crontab" else real_exists(path),
    )
    real_listdir = sentinel_module.os.listdir
    monkeypatch.setattr(
        sentinel_module.os, "listdir",
        lambda path: [] if path == "/etc/cron.d/" else real_listdir(path),
    )

    alerts = []
    monkeypatch.setattr(
        sentinel_module, "send_alert",
        lambda alert_type, details, logger=None: alerts.append((alert_type, details)),
    )
    logger = logging.getLogger("sentinel-test-cron")

    assert sentinel_module.cron_monitor_check({}, logger) == [
        {"type": "new", "entry": "new-digest-entry"}
    ]
    assert [item[0] for item in alerts] == ["NEW_CRON"]

    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(alerts) == 1

    # Restoring the original trusted baseline resolves the finding silently.
    current["text"] = "trusted-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert [item[0] for item in alerts] == ["NEW_CRON"]

    # Reintroducing the same drift after resolution must alert again.
    current["text"] = "trusted-entry\nnew-digest-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == [
        {"type": "new", "entry": "new-digest-entry"}
    ]
    assert [item[0] for item in alerts] == ["NEW_CRON", "NEW_CRON"]

    # Removing a trusted baseline entry is a distinct active finding.
    current["text"] = "new-digest-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == [
        {"type": "removed", "entry": "trusted-entry"}
    ]
    assert [item[0] for item in alerts] == ["NEW_CRON", "NEW_CRON", "REMOVED_CRON"]
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(alerts) == 3


def test_finding_state_file_is_private_and_resolves(sentinel_data):
    from modules.finding_state import newly_active

    assert newly_active("test", {"finding": "fingerprint"}) == {"finding"}
    state_path = sentinel_data / "finding_state_test.json"
    assert state_path.exists()
    assert state_path.stat().st_mode & 0o777 == 0o600
    assert newly_active("test", {"finding": "fingerprint"}) == set()
    assert newly_active("test", {}) == set()
    assert newly_active("test", {"finding": "fingerprint"}) == {"finding"}
