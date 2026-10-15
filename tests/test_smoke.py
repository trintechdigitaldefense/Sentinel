"""Smoke tests — SENTINEL must import and compile core paths."""
from __future__ import annotations

import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sentinel_compiles():
    py_compile.compile(str(ROOT / "sentinel.py"), doraise=True)


def test_setup_compiles():
    py_compile.compile(str(ROOT / "setup.py"), doraise=True)


def test_no_b64_blobs():
    blobs = list(ROOT.rglob("*.b64"))
    # ignore anything under .git if present
    blobs = [b for b in blobs if ".git" not in b.parts]
    assert blobs == [], f"Found base64 blobs: {blobs}"


def test_version_string():
    src = (ROOT / "sentinel.py").read_text(errors="ignore")
    assert "__version__" in src
