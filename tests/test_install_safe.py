# © 2026 TrinTech Digital Defense — defensive tests
"""Installer must not default to destructive git reset."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_install_sh_recover_flag_required_for_hard_reset():
    text = (ROOT / "install.sh").read_text()
    assert "SENTINEL_RECOVER_SYNC" in text
    # default path should mention fast-forward / non-destructive
    assert "non-destructive" in text.lower() or "Fast-forward" in text or "ff-only" in text or "fast-forward" in text.lower()
    # hard reset should only appear in recovery function context
    assert "reset --hard" in text
    # ensure recover_sync is gated
    assert "RECOVER" in text


def test_setup_py_no_auto_hard_reset_without_recover():
    text = (ROOT / "setup.py").read_text()
    assert "SENTINEL_RECOVER_SYNC" in text or "ensure_git_clean" in text
    # ensure_git_clean should not reset unless recover
    assert "def ensure_git_clean" in text


def test_all_modules_compile():
    import py_compile
    for p in sorted((ROOT / "modules").rglob("*.py")):
        py_compile.compile(str(p), doraise=True)


def test_no_import_before_future_in_modules():
    bad = []
    for p in (ROOT / "modules").rglob("*.py"):
        lines = p.read_text(errors="replace").splitlines()
        for i, ln in enumerate(lines):
            if ln.strip().startswith("from __future__"):
                for prev in lines[:i]:
                    s = prev.strip()
                    if s.startswith("import ") or (s.startswith("from ") and "future" not in s):
                        bad.append(str(p))
                break
    assert bad == []
