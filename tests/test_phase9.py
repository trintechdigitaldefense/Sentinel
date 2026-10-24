# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 9 MSP daily use tests."""
from __future__ import annotations

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_digest_and_client_note(env):
    from modules import cases
    from modules.msp_digest import format_digest, collect_open_cases
    from modules.client_notes import render_client_note, save_client_note

    cases.init_db()
    r = cases.create_case(title="USB anomaly on front desk", severity="high", source="test")
    assert r["ok"]
    cid = r["case"]["id"]
    text = format_digest()
    assert cid in text or "Open:" in text
    assert collect_open_cases()
    note = render_client_note(r["case"], client_name="Demo Co")
    assert "Demo Co" in note
    assert "USB anomaly" in note
    saved = save_client_note(cid, client_name="Demo Co")
    assert saved["ok"] and saved.get("path")


def test_false_positive_suppression(env):
    from modules import cases, suppressions

    cases.init_db()
    r = cases.create_case(title="backup-job noise /tmp/backup", severity="medium", source="usb")
    cid = r["case"]["id"]
    st = cases.set_status(cid, "false_positive", actor="test")
    assert st["ok"]
    assert st.get("suppression", {}).get("ok") is True
    rules = suppressions.list_rules()
    assert rules
