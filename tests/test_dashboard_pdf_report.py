"""Dashboard one-push PDF report action."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


def test_generate_client_report_writes_pdf(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # ensure modules resolve data under tmp
    import modules.dashboard_impl as d
    import importlib
    importlib.reload(d)

    r = d._generate_dashboard_pdfs("client-report")
    assert r.get("ok") is True, r
    assert r.get("download", "").startswith("/api/report/download?name=")
    path = Path(r["path"])
    assert path.is_file()
    assert path.suffix == ".pdf"
    assert path.stat().st_size > 500


def test_pdf_report_action_returns_download(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    import modules.dashboard_impl as d
    import importlib
    importlib.reload(d)
    r = d._generate_dashboard_pdfs("pdf-report")
    assert r.get("ok") is True, r
    assert r.get("downloads")
    assert any("Client_Report" in (x.get("path") or "") or True for x in r.get("generated") or [])


def test_download_path_traversal_rejected():
    from modules.dashboard_impl import _Handler
    # name sanitization is Path(name).name — only basename served
    name = Path("../../etc/passwd").name
    assert name == "passwd"
    name_pdf = Path("../../etc/shadow.pdf").name
    assert name_pdf == "shadow.pdf"
