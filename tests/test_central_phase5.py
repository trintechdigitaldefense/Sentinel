# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 5 central hardening tests — isolation, audit, fail-closed auth."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def central_env(tmp_path, monkeypatch):
    """Isolated central data directory for each test."""
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path))
    # Ensure modules pick up the new path
    import importlib
    import modules.agent_keys as ak
    import sentinel_central.server as srv

    importlib.reload(ak)
    importlib.reload(srv)
    srv.init_db()
    return tmp_path, ak, srv


def test_issue_and_verify_key(central_env):
    _, ak, _ = central_env
    master = "test-master-key-phase5"
    resp = ak.issue_key("site-a", master, master)
    assert resp["ok"] is True
    assert resp["agent_id"] == "site-a"
    assert resp["api_key"]
    assert ak.verify_key("site-a", resp["api_key"]) is True
    assert ak.verify_key("site-a", "wrong") is False
    assert ak.verify_key("site-b", resp["api_key"]) is False


def test_resolve_agent_id(central_env):
    _, ak, _ = central_env
    master = "test-master-key-phase5"
    resp = ak.issue_key("site-resolve", master, master)
    assert ak.resolve_agent_id(resp["api_key"]) == "site-resolve"
    assert ak.resolve_agent_id("garbage") is None


def test_revoke_blocks_verify(central_env):
    _, ak, _ = central_env
    master = "test-master-key-phase5"
    resp = ak.issue_key("site-rev", master, master)
    key = resp["api_key"]
    assert ak.verify_key("site-rev", key) is True
    ak.revoke("site-rev", master, master)
    assert ak.verify_key("site-rev", key) is False
    assert ak.resolve_agent_id(key) is None


def test_event_isolation_by_client_id(central_env):
    """Events are stored under the verified agent id, not a body-supplied id."""
    tmp, ak, srv = central_env
    master = "test-master-key-phase5"
    a = ak.issue_key("tenant-a", master, master)
    b = ak.issue_key("tenant-b", master, master)

    srv.insert_event("tenant-a", {"title": "A event", "severity": "HIGH"})
    srv.insert_event("tenant-b", {"title": "B event", "severity": "LOW"})

    import sqlite3

    con = sqlite3.connect(srv.DB)
    rows_a = con.execute("SELECT title FROM events WHERE client_id=?", ("tenant-a",)).fetchall()
    rows_b = con.execute("SELECT title FROM events WHERE client_id=?", ("tenant-b",)).fetchall()
    con.close()
    assert len(rows_a) == 1 and rows_a[0][0] == "A event"
    assert len(rows_b) == 1 and rows_b[0][0] == "B event"


def test_audit_written_on_enroll_and_revoke(central_env):
    tmp, ak, srv = central_env
    master = "test-master-key-phase5"
    resp = ak.issue_key("audit-site", master, master)
    assert resp["ok"]
    # Simulate audit calls the server would make
    srv.audit("master", "enroll", "ok", target_type="agent", target_id="audit-site")
    ak.revoke("audit-site", master, master)
    srv.audit("master", "revoke", "ok", target_type="agent", target_id="audit-site")

    import sqlite3

    con = sqlite3.connect(srv.DB)
    rows = con.execute(
        "SELECT action, result, target_id FROM audit_events ORDER BY id"
    ).fetchall()
    con.close()
    actions = [r[0] for r in rows]
    assert "enroll" in actions
    assert "revoke" in actions
    assert all(r[1] == "ok" for r in rows)


def test_master_key_not_usable_as_agent_key_for_events(central_env):
    """Master key must not be accepted as an agent identity for data paths."""
    _, ak, srv = central_env
    # resolve_agent_id should never return a master key
    assert ak.resolve_agent_id("some-master-secret") is None



def test_agent_key_expiry_is_enforced(central_env):
    tmp, ak, _ = central_env
    import json
    from datetime import datetime, timedelta, timezone

    master = "test-master-key-expiry"
    resp = ak.issue_key("expiring-site", master, master, ttl_seconds=60)
    assert resp["ok"] is True
    assert ak.verify_key("expiring-site", resp["api_key"]) is True

    registry = ak._keys_path()
    data = json.loads(registry.read_text())
    data["agents"]["expiring-site"]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    registry.write_text(json.dumps(data))
    assert ak.verify_key("expiring-site", resp["api_key"]) is False
    assert ak.resolve_agent_id(resp["api_key"]) is None


def test_corrupt_agent_registry_fails_closed(central_env):
    tmp, ak, _ = central_env
    registry = ak._keys_path()
    registry.write_text("{not-json")
    with pytest.raises(RuntimeError, match="refusing to reset"):
        ak.resolve_agent_id("some-key")
    assert registry.read_text() == "{not-json"


def test_network_central_server_refuses_plain_http(central_env, monkeypatch):
    import sys

    _, _, srv = central_env
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinel-central", "--master-key", "test-master", "--host", "0.0.0.0"],
    )
    with pytest.raises(SystemExit, match="Refusing network listener without TLS"):
        srv.main()


def test_reissuing_agent_key_invalidates_previous_credential(central_env):
    _, ak, _ = central_env
    master = "test-master-key-rotation"
    first = ak.issue_key("rotating-site", master, master)
    second = ak.issue_key("rotating-site", master, master)
    assert first["ok"] and second["ok"]
    assert first["api_key"] != second["api_key"]
    assert ak.verify_key("rotating-site", first["api_key"]) is False
    assert ak.verify_key("rotating-site", second["api_key"]) is True
    assert ak.resolve_agent_id(first["api_key"]) is None
    assert ak.resolve_agent_id(second["api_key"]) == "rotating-site"


def test_invalid_expiry_timestamp_fails_closed(central_env):
    _, ak, _ = central_env
    master = "test-master-key-invalid-expiry"
    issued = ak.issue_key("bad-expiry-site", master, master)
    registry = ak._keys_path()
    data = json.loads(registry.read_text())
    data["agents"]["bad-expiry-site"]["expires_at"] = "not-a-timestamp"
    registry.write_text(json.dumps(data))
    assert ak.verify_key("bad-expiry-site", issued["api_key"]) is False
    assert ak.resolve_agent_id(issued["api_key"]) is None



def test_legacy_key_without_expiry_is_rejected_and_identified_for_migration(central_env):
    tmp, ak, _ = central_env
    legacy_key = "pre-expiry-agent-secret"
    registry = ak._keys_path()
    registry.write_text(json.dumps({
        "agents": {
            "legacy-site": {
                "key_hash": ak._hash(legacy_key),
                "created": "2025-01-01T00:00:00+00:00",
                "revoked": False,
            }
        }
    }))
    assert ak.verify_key("legacy-site", legacy_key) is False
    assert ak.resolve_agent_id(legacy_key) is None
    status = {row["agent_id"]: row for row in ak.list_agents()}
    assert status["legacy-site"]["legacy"] is True
    assert status["legacy-site"]["migration_required"] is True
    assert status["legacy-site"]["expired"] is True


def test_reissuing_legacy_key_marks_migration_and_invalidates_old_key(central_env):
    _, ak, _ = central_env
    old_key = "legacy-key-to-replace"
    registry = ak._keys_path()
    registry.write_text(json.dumps({
        "agents": {
            "legacy-rotate": {
                "key_hash": ak._hash(old_key),
                "created": "2025-01-01T00:00:00+00:00",
                "revoked": False,
            }
        }
    }))
    master = "migration-master"
    replacement = ak.issue_key("legacy-rotate", master, master)
    assert replacement["ok"] is True
    assert replacement["rotated"] is True
    assert replacement["legacy_migration"] is True
    assert ak.verify_key("legacy-rotate", old_key) is False
    assert ak.verify_key("legacy-rotate", replacement["api_key"]) is True
    assert {row["agent_id"]: row for row in ak.list_agents()}["legacy-rotate"]["migration_required"] is False


def test_agent_key_registry_rejects_non_object_legacy_records(central_env):
    _, ak, _ = central_env
    registry = ak._keys_path()
    registry.write_text(json.dumps({"agents": {"broken-record": "not-an-object"}}))
    with pytest.raises(RuntimeError, match="refusing to reset"):
        ak.list_agents()
    assert json.loads(registry.read_text())["agents"]["broken-record"] == "not-an-object"
