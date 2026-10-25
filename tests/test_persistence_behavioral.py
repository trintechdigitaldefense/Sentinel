# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Persistence + behavioral shell smoke tests (no network)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    return tmp_path


def test_persistence_snapshot_and_baseline(env):
    from modules.persistence_hunt import snapshot, create_baseline, check, status
    snap = snapshot()
    assert isinstance(snap, dict)
    r = create_baseline()
    assert r["ok"] is True
    assert r["count"] >= 0
    st = status()
    assert st["baseline_exists"] is True
    c = check()
    assert c["ok"] is True
    assert c.get("count", 0) == 0  # no drift right after baseline


def test_suid_baseline(env):
    from modules.fim_suid import build_baseline, check, status
    r = build_baseline()
    assert r["ok"] is True
    st = status()
    assert st["baseline_exists"] is True
    assert check() == [] or isinstance(check(), list)


def test_behavioral_scan_runs(env):
    from modules.behavioral_shell import scan
    hits = scan()
    assert isinstance(hits, list)


def test_firewall_lockout_helpers(env):
    from modules.firewall import detect_operator_ips, block_ip, status
    ips = detect_operator_ips()
    assert isinstance(ips, list)
    s = status()
    assert s.get("lockout_guard") is True
    assert s.get("ipv6") is True
    # dry-run still works
    assert block_ip("198.51.100.10", confirm=False).get("dry_run") is True


def test_fim_realtime_helpers():
    from modules.fim_realtime import watch_dirs, has_inotifywait
    dirs = watch_dirs({})
    assert isinstance(dirs, list)
    assert isinstance(has_inotifywait(), bool)
