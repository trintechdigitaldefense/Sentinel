# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 7 case / triage tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules import cases


@pytest.fixture
def case_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    cases.init_db()
    return tmp_path


def test_create_and_get(case_env):
    r = cases.create_case(title="Canary triggered", severity="high", source="sentinel_local", actor="jason")
    assert r["ok"] is True
    cid = r["case"]["id"]
    assert cid.startswith("CASE-")
    got = cases.get_case(cid)
    assert got is not None
    assert got["title"] == "Canary triggered"
    assert got["status"] == "new"
    assert got["severity"] == "high"
    assert any(a["action"] == "create" for a in got["audit"])


def test_status_assign_note(case_env):
    r = cases.create_case(title="SSH brute", severity="medium")
    cid = r["case"]["id"]
    assert cases.set_status(cid, "investigating")["ok"]
    assert cases.assign(cid, "analyst-1")["ok"]
    assert cases.add_note(cid, "Checking auth logs", author="analyst-1")["ok"]
    got = cases.get_case(cid)
    assert got["status"] == "investigating"
    assert got["assignee"] == "analyst-1"
    assert len(got["notes"]) == 1
    actions = [a["action"] for a in got["audit"]]
    assert "status_change" in actions
    assert "assign" in actions
    assert "note_add" in actions


def test_invalid_status(case_env):
    r = cases.create_case(title="x")
    cid = r["case"]["id"]
    bad = cases.set_status(cid, "nuked")
    assert bad["ok"] is False


def test_list_filter(case_env):
    cases.create_case(title="A", severity="low")
    b = cases.create_case(title="B", severity="high")["case"]["id"]
    cases.set_status(b, "resolved")
    open_ones = cases.list_cases(status="new")
    assert all(c["status"] == "new" for c in open_ones)
    closed = cases.list_cases(status="resolved")
    assert any(c["id"] == b for c in closed)


def test_evidence_export(case_env):
    data = case_env / "data"
    data.mkdir(exist_ok=True)
    (data / "alerts.log").write_text(
        json.dumps({"fp": "fp1", "title": "Canary", "severity": "HIGH"}) + "\n"
    )
    r = cases.create_case(title="Evidence test", alert_refs=["fp1"])
    cid = r["case"]["id"]
    exp = cases.export_evidence(cid)
    assert exp["ok"] is True
    z = Path(exp["path"])
    assert z.exists()
    assert exp["sha256"]
    sha_file = z.with_suffix(z.suffix + ".sha256")
    assert sha_file.exists()
    got = cases.get_case(cid)
    assert any(a["action"] == "evidence_export" for a in got["audit"])


def test_create_from_normalized(case_env):
    alert = {
        "id": "sentinel-abc",
        "source": "sentinel_local",
        "source_event_id": "abc",
        "severity": "critical",
        "title": "Reverse shell",
        "detail": "bash -i detected",
    }
    r = cases.create_from_normalized_alert(alert)
    assert r["ok"]
    assert r["case"]["severity"] == "critical"
    assert r["case"]["source"] == "sentinel_local"
