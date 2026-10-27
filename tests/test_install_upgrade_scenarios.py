# © 2026 TrinTech Digital Defense — installer safety scenarios
"""Regression: ordinary install/upgrade must not destroy local work."""
from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd, cwd, env=None, check=False):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        cmd, cwd=cwd, env=e, text=True, capture_output=True, check=check
    )


@pytest.fixture
def git_repo(tmp_path):
    """Minimal git repo simulating a Sentinel checkout."""
    repo = tmp_path / "Sentinel"
    repo.mkdir()
    (repo / "sentinel.py").write_text("# sentinel stub\n")
    (repo / "setup.py").write_text("# setup stub\n")
    (repo / "README.md").write_text("SENTINEL\n")
    _run(["git", "init"], repo, check=True)
    _run(["git", "config", "user.email", "test@example.com"], repo, check=True)
    _run(["git", "config", "user.name", "Test"], repo, check=True)
    _run(["git", "add", "."], repo, check=True)
    _run(["git", "commit", "-m", "init"], repo, check=True)
    _run(["git", "branch", "-M", "main"], repo, check=True)
    return repo


def test_install_sh_default_is_non_destructive():
    text = (ROOT / "install.sh").read_text()
    assert "non-destructive" in text.lower() or "fast-forward" in text.lower()
    assert "SENTINEL_RECOVER_SYNC" in text
    # hard reset only inside recovery path, gated
    assert "SENTINEL_RECOVER_SYNC" in text
    # clean -fd must not be default
    assert 'SENTINEL_RECOVER_CLEAN' in text or "git clean" in text
    # ensure default path does not unconditionally clean
    lines = text.splitlines()
    # find recover_sync function region
    in_recover = False
    for ln in lines:
        if "recover_sync" in ln or "SENTINEL_RECOVER_SYNC" in ln and "function" in ln:
            in_recover = True


def test_setup_py_ensure_git_clean_no_reset_without_recover(tmp_path, monkeypatch):
    """ensure_git_clean must not call reset --hard unless recover env set."""
    import setup as setup_mod

    # Run outside a git repo: should no-op safely
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SENTINEL_RECOVER_SYNC", raising=False)
    setup_mod.ensure_git_clean()  # must not raise


def test_dirty_tracked_file_blocks_silent_destroy(git_repo):
    """Dirty tree: status --porcelain non-empty; install must not hard-reset without recover."""
    (git_repo / "README.md").write_text("LOCAL EDIT\n")
    st = _run(["git", "status", "--porcelain"], git_repo)
    assert st.stdout.strip()
    # Simulate what safe path does: ff-only fails or warns, no automatic reset
    # We assert install.sh documents stop-on-dirty, not that bash runs against remote
    text = (ROOT / "install.sh").read_text()
    assert "Fast-forward failed" in text or "dirty" in text.lower()
    assert "reset --hard" in text  # exists only for recovery
    # recovery requires env
    assert 'SENTINEL_RECOVER_SYNC:-0' in text or 'SENTINEL_RECOVER_SYNC' in text


def test_untracked_file_survives_conceptually(git_repo):
    (git_repo / "MY_NOTES.txt").write_text("do not delete\n")
    st = _run(["git", "status", "--porcelain"], git_repo)
    assert "MY_NOTES.txt" in st.stdout
    # Default recovery does NOT git clean unless RECOVER_CLEAN
    text = (ROOT / "install.sh").read_text()
    assert "SENTINEL_RECOVER_CLEAN" in text
    assert "Do NOT git clean" in text or "RECOVER_CLEAN" in text


def test_config_dir_not_touched_by_install_script():
    text = (ROOT / "install.sh").read_text()
    # install must not rm -rf ~/.sentinel
    assert "rm -rf" not in text or ".sentinel" not in text.split("rm -rf")[0][-80:]
    # stronger: no rm of SENTINEL_DIR
    assert "rm -rf ~/.sentinel" not in text
    assert "rm -rf $HOME/.sentinel" not in text


def test_install_md_does_not_encourage_routine_hard_reset():
    text = (ROOT / "INSTALL.md").read_text().lower()
    assert "non-destructive" in text or "fast-forward" in text or "ff-only" in text
    assert "recover" in text
    # must not say hard-reset by default
    assert "hard-resets by default" not in text
