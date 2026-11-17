# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Regression tests for active-finding alert deduplication."""
from __future__ import annotations

import json
import logging


def test_finding_state_persists_resolves_and_realerts(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    from modules.finding_state import newly_active

    assert newly_active("test", {"finding": "one"}) == {"finding"}
    state = tmp_path / "data" / "finding_state_test.json"
    assert state.stat().st_mode & 0o777 == 0o600
    assert newly_active("test", {"finding": "one"}) == set()
    assert newly_active("test", {}) == set()
    assert newly_active("test", {"finding": "one"}) == {"finding"}
    assert newly_active("test", {"finding": "two"}) == {"finding"}


def test_persistence_change_alerts_once_until_resolved(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import persistence_hunt

    path = "/tmp/sentinel-test-profile"
    original = {"sha256": "baseline-hash", "type": "rc"}
    changed = {"sha256": "changed-hash", "type": "rc"}
    baseline = {"created": "test", "count": 1, "entries": {path: original}}
    persistence_hunt.baseline_path().write_text(json.dumps(baseline))
    current = {path: changed}
    monkeypatch.setattr(persistence_hunt, "snapshot", lambda: dict(current))

    alerts = []
    def send_alert(kind, details):
        alerts.append((kind, details))
        return {"ok": True}
    assert [e["type"] for e in persistence_hunt.check(send_alert)["events"]] == [
        "RC_FILE_CHANGED"
    ]
    assert persistence_hunt.check(send_alert)["events"] == []
    assert len(alerts) == 1

    current[path] = original
    assert persistence_hunt.check(send_alert)["events"] == []
    current[path] = changed
    assert [e["type"] for e in persistence_hunt.check(send_alert)["events"]] == [
        "RC_FILE_CHANGED"
    ]
    assert len(alerts) == 2


def test_persistence_changed_fingerprint_alerts_again(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import persistence_hunt

    path = "/tmp/sentinel-test-profile"
    baseline = {"created": "test", "count": 1, "entries": {
        path: {"sha256": "baseline-hash", "type": "rc"}
    }}
    persistence_hunt.baseline_path().write_text(json.dumps(baseline))
    current = {path: {"sha256": "first-change", "type": "rc"}}
    monkeypatch.setattr(persistence_hunt, "snapshot", lambda: dict(current))
    alerts = []
    def send_alert(kind, details):
        alerts.append((kind, details))
        return {"ok": True}

    assert persistence_hunt.check(send_alert)["count"] == 1
    current[path] = {"sha256": "second-change", "type": "rc"}
    assert persistence_hunt.check(send_alert)["count"] == 1
    assert len(alerts) == 2



def test_persistence_failed_alert_is_retried_until_handled(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import persistence_hunt

    path = "/tmp/sentinel-retry-profile"
    baseline = {
        "created": "test",
        "count": 1,
        "entries": {
            path: {"sha256": "baseline-hash", "type": "rc"}
        },
    }
    persistence_hunt.baseline_path().write_text(json.dumps(baseline))
    monkeypatch.setattr(
        persistence_hunt,
        "snapshot",
        lambda: {path: {"sha256": "changed-hash", "type": "rc"}},
    )

    attempts = []

    def flaky_alert(kind, details):
        attempts.append((kind, details))
        return {"ok": len(attempts) > 1}

    first = persistence_hunt.check(flaky_alert)
    second = persistence_hunt.check(flaky_alert)
    third = persistence_hunt.check(flaky_alert)

    assert first["count"] == 1
    assert second["count"] == 1
    assert third["events"] == []
    assert len(attempts) == 2

def _mock_cron_inputs(monkeypatch, sentinel_module, current):
    monkeypatch.setattr(
        sentinel_module, "run_cmd", lambda *args, **kwargs: current["text"]
    )
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


def test_cron_change_alerts_once_until_resolved(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    import sentinel as sentinel_module

    baseline_path = tmp_path / "data" / "cron_baseline.json"
    baseline_path.write_text(json.dumps([
        {"source": "root_crontab", "entry": "trusted-entry"}
    ]))
    monkeypatch.setattr(sentinel_module, "CRON_BASELINE", baseline_path)
    current = {"text": "trusted-entry\nnew-digest-entry\n"}
    _mock_cron_inputs(monkeypatch, sentinel_module, current)

    alerts = []
    def successful_alert(kind, details, logger=None):
        alerts.append((kind, details))
        return {"ok": True}

    monkeypatch.setattr(
        sentinel_module, "send_alert", successful_alert,
    )
    logger = logging.getLogger("sentinel-test-cron")

    assert sentinel_module.cron_monitor_check({}, logger) == [
        {"type": "new", "entry": "new-digest-entry"}
    ]
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(alerts) == 1

    current["text"] = "trusted-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == []
    current["text"] = "trusted-entry\nnew-digest-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == [
        {"type": "new", "entry": "new-digest-entry"}
    ]
    assert len(alerts) == 2



def test_cron_failed_alert_is_retried_until_handled(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    import sentinel as sentinel_module

    baseline_path = tmp_path / "data" / "cron_baseline.json"
    baseline_path.write_text(json.dumps([
        {"source": "root_crontab", "entry": "trusted-entry"}
    ]))
    monkeypatch.setattr(sentinel_module, "CRON_BASELINE", baseline_path)
    current = {"text": "trusted-entry\nnew-retry-entry\n"}
    _mock_cron_inputs(monkeypatch, sentinel_module, current)

    attempts = []

    def flaky_alert(kind, details, logger=None):
        attempts.append((kind, details))
        return {"ok": len(attempts) > 1}

    monkeypatch.setattr(sentinel_module, "send_alert", flaky_alert)
    logger = logging.getLogger("sentinel-test-cron-retry")

    expected = [{"type": "new", "entry": "new-retry-entry"}]
    assert sentinel_module.cron_monitor_check({}, logger) == expected
    assert sentinel_module.cron_monitor_check({}, logger) == expected
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(attempts) == 2

def test_corrupt_cron_baseline_is_never_overwritten(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    import sentinel as sentinel_module

    baseline_path = tmp_path / "data" / "cron_baseline.json"
    corrupt = "{ this is not valid JSON"
    baseline_path.write_text(corrupt)
    monkeypatch.setattr(sentinel_module, "CRON_BASELINE", baseline_path)
    current = {"text": "untrusted-entry\n"}
    _mock_cron_inputs(monkeypatch, sentinel_module, current)

    alerts = []
    monkeypatch.setattr(
        sentinel_module, "send_alert",
        lambda *args, **kwargs: alerts.append(args),
    )
    result = sentinel_module.cron_monitor_check(
        {}, logging.getLogger("sentinel-test-corrupt-cron")
    )
    assert result == []
    assert alerts == []
    assert baseline_path.read_text() == corrupt


def test_invalid_cron_baseline_structure_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()
    import sentinel as sentinel_module

    baseline_path = tmp_path / "data" / "cron_baseline.json"
    corrupt = json.dumps({"unexpected": "format"})
    baseline_path.write_text(corrupt)
    monkeypatch.setattr(sentinel_module, "CRON_BASELINE", baseline_path)
    current = {"text": "untrusted-entry\n"}
    _mock_cron_inputs(monkeypatch, sentinel_module, current)

    sentinel_module.cron_monitor_check(
        {}, logging.getLogger("sentinel-test-invalid-cron")
    )
    assert baseline_path.read_text() == corrupt


def test_corrupt_persistence_baseline_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import persistence_hunt

    path = persistence_hunt.baseline_path()
    corrupt = "{ invalid"
    path.write_text(corrupt)
    monkeypatch.setattr(persistence_hunt, "snapshot", lambda: {})
    result = persistence_hunt.check()
    assert result["ok"] is False
    assert path.read_text() == corrupt


def test_finding_state_directory_failure_fails_open(monkeypatch):
    from modules import finding_state

    def fail_state_path(namespace):
        raise PermissionError("simulated state-directory permission failure")

    monkeypatch.setattr(finding_state, "_state_path", fail_state_path)

    assert finding_state.newly_active(
        "test", {"active-finding": "fingerprint"}
    ) == {"active-finding"}


def test_persistence_complete_notification_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    from modules import persistence_hunt

    path = "/tmp/sentinel-complete-lifecycle"
    original = {"sha256": "baseline-hash", "type": "rc"}
    changed = {"sha256": "changed-hash", "type": "rc"}

    persistence_hunt.baseline_path().write_text(json.dumps({
        "created": "test",
        "count": 1,
        "entries": {path: original},
    }))

    current = {path: changed}
    monkeypatch.setattr(
        persistence_hunt, "snapshot", lambda: dict(current)
    )

    attempts = []

    def flaky_alert(kind, details):
        attempts.append((kind, details))
        return {"ok": len(attempts) > 1}

    # 1. First notification fails.
    first = persistence_hunt.check(flaky_alert)
    assert first["count"] == 1
    assert len(attempts) == 1

    # 2. Finding remains pending; the next attempt is made.
    second = persistence_hunt.check(flaky_alert)
    assert second["count"] == 1
    assert len(attempts) == 2

    # 3. Notification succeeded; unchanged finding is not sent again.
    third = persistence_hunt.check(flaky_alert)
    assert third["events"] == []
    assert len(attempts) == 2

    # 4. Finding resolves.
    current[path] = original
    assert persistence_hunt.check(flaky_alert)["events"] == []
    assert len(attempts) == 2

    # 5. Finding recurs and generates a fresh notification.
    current[path] = changed
    recurring = persistence_hunt.check(flaky_alert)
    assert recurring["count"] == 1
    assert len(attempts) == 3


def test_cron_complete_notification_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    (tmp_path / "data").mkdir()

    import sentinel as sentinel_module

    baseline_path = tmp_path / "data" / "cron_baseline.json"
    baseline_path.write_text(json.dumps([
        {"source": "root_crontab", "entry": "trusted-entry"}
    ]))

    monkeypatch.setattr(
        sentinel_module, "CRON_BASELINE", baseline_path
    )

    current = {"text": "trusted-entry\nnew-lifecycle-entry\n"}
    _mock_cron_inputs(monkeypatch, sentinel_module, current)

    attempts = []

    def flaky_alert(kind, details, logger=None):
        attempts.append((kind, details))
        return {"ok": len(attempts) > 1}

    monkeypatch.setattr(
        sentinel_module, "send_alert", flaky_alert
    )
    logger = logging.getLogger("sentinel-test-complete-cron")

    expected = [
        {"type": "new", "entry": "new-lifecycle-entry"}
    ]

    # 1. First notification fails.
    assert sentinel_module.cron_monitor_check({}, logger) == expected
    assert len(attempts) == 1

    # 2. Finding remains pending and is retried.
    assert sentinel_module.cron_monitor_check({}, logger) == expected
    assert len(attempts) == 2

    # 3. Notification succeeded; unchanged finding is not repeated.
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(attempts) == 2

    # 4. Finding resolves.
    current["text"] = "trusted-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == []
    assert len(attempts) == 2

    # 5. Finding recurs and generates a fresh notification.
    current["text"] = "trusted-entry\nnew-lifecycle-entry\n"
    assert sentinel_module.cron_monitor_check({}, logger) == expected
    assert len(attempts) == 3
