# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 10 tests."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_digest_job_saves(env):
    from modules import cases
    from modules.digest_cron import run_digest_job, crontab_line

    cases.init_db()
    cases.create_case(title="p10", severity="medium", source="t")
    r = run_digest_job(via="none")
    assert r.get("saved")
    assert Path(r["saved"]).exists()
    assert "digest_cron" in crontab_line()


def test_enable_local(env):
    from modules.connector_enable import enable_local, load_config

    r = enable_local(auto_case=True)
    assert r["ok"]
    assert load_config()["connectors"]["sentinel_local"]["auto_case"] is True
