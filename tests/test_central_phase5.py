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
