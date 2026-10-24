# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 6 connector tests — schema, local reference, isolation of normalize."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.connectors.base import NormalizedAlert, Severity
from modules.connectors.sentinel_local import SentinelLocalConnector
from modules.connectors.wazuh import WazuhConnector
from modules.connectors import get_connector


def test_severity_mapping():
    assert Severity.from_raw("HIGH") == Severity.HIGH
    assert Severity.from_raw(12) == Severity.CRITICAL  # Wazuh-style level
    assert Severity.from_raw("info") == Severity.INFORMATIONAL
    assert Severity.from_raw(None) == Severity.INFORMATIONAL


def test_normalized_alert_to_dict():
    a = NormalizedAlert(
        id="x",
        source="test",
        source_event_id="1",
        severity=Severity.HIGH,
        title="Canary",
        occurred_at="2026-10-24T00:00:00+00:00",
        received_at="2026-10-24T00:00:01+00:00",
    )
    d = a.to_dict()
    assert d["severity"] == "high"
    assert d["title"] == "Canary"


def test_sentinel_local_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    c = SentinelLocalConnector({})
    h = c.health_check()
    assert h.ok is True
    alerts, nxt = c.fetch_events(limit=10)
    assert alerts == []
    assert nxt is None


def test_sentinel_local_fetch_and_normalize(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    data = tmp_path / "data"
    data.mkdir()
    log = data / "alerts.log"
    rows = [
        {"ts": "2026-10-24T10:00:00", "severity": "HIGH", "title": "Canary hit", "detail": "file opened", "fp": "abc1"},
        {"ts": "2026-10-24T11:00:00", "severity": "INFO", "title": "Heartbeat", "fp": "abc2"},
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    c = SentinelLocalConnector({})
    alerts, nxt = c.fetch_events(limit=10)
    assert len(alerts) == 2
    assert alerts[0].source == "sentinel_local"
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].title == "Canary hit"
    assert alerts[0].source_event_id == "abc1"
    assert nxt is None

    # pagination
    page1, c1 = c.fetch_events(limit=1)
    assert len(page1) == 1
    assert c1 is not None
    page2, c2 = c.fetch_events(cursor=c1, limit=1)
    assert len(page2) == 1
    assert page2[0].title == "Heartbeat"


def test_wazuh_normalize_sample():
    c = WazuhConnector({})
    raw = {
        "id": "1600000000.123",
        "timestamp": "2026-10-24T12:00:00+00:00",
        "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed"},
        "agent": {"id": "001", "name": "web-01"},
        "full_log": "File /etc/passwd modified",
    }
    n = c.normalize(raw)
    assert n is not None
    assert n.source == "wazuh"
    assert n.severity == Severity.MEDIUM
    assert "Integrity" in n.title
    assert n.asset_id == "001"
    assert n.rule_id == "550"


def test_wazuh_health_not_configured():
    c = WazuhConnector({})
    h = c.health_check()
    assert h.ok is False
    assert "not configured" in h.message


def test_factory():
    c = get_connector("sentinel_local")
    assert c.name == "sentinel_local"
    with pytest.raises(ValueError):
        get_connector("unknown-source")
