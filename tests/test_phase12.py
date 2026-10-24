# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 12 foundation tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_tenants(env):
    from modules import tenants

    r = tenants.create_tenant("Acme TT")
    assert r["ok"] and r["tenant"]["id"].startswith("tnt-")
    assert any(t["name"] == "Acme TT" for t in tenants.list_tenants())


def test_auto_response_off_by_default(env):
    from modules.auto_response import evaluate_case

    d = evaluate_case({"severity": "critical", "title": "x"})
    assert d["would_act"] is False


def test_auto_response_not_silent(env):
    from modules import cases
    from modules.auto_response import maybe_auto_respond

    (Path(env) / "config.json").write_text(
        json.dumps(
            {
                "response": {
                    "enabled": True,
                    "auto_enabled": True,
                    "auto_min_severity": "critical",
                    "auto_actions": ["annotate"],
                    "auto_max_per_hour": 10,
                }
            }
        )
    )
    cases.init_db()
    c = cases.create_case(title="crit", severity="critical")
    r = maybe_auto_respond(c["case"]["id"])
    assert r.get("silent") is False
    assert r.get("acted") is True


def test_ueba_lite_shape(env):
    from modules.ueba_lite import score_hosts

    r = score_hosts()
    assert r["ok"]
    assert "hosts" in r
