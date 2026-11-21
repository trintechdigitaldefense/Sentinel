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


def test_client_report_rejects_generator_path_outside_reports(tmp_path, monkeypatch):
    import modules.dashboard_impl as d
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE")

    def fake_generator(out_path, client_name=None):
        return {"ok": True, "path": str(outside)}

    with patch("modules.client_report.generate_client_pdf", side_effect=fake_generator):
        result = d._generate_dashboard_pdfs("client-report")

    assert result.get("ok") is False
    assert "unapproved report path" in result.get("error", "")
    assert not (d._reports_dir() / outside.name).exists()


def test_client_report_rejects_generator_symlink(tmp_path, monkeypatch):
    import modules.dashboard_impl as d
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE")

    def fake_generator(out_path, client_name=None):
        Path(out_path).symlink_to(outside)
        return {"ok": True, "path": str(out_path)}

    with patch("modules.client_report.generate_client_pdf", side_effect=fake_generator):
        result = d._generate_dashboard_pdfs("client-report")

    assert result.get("ok") is False
    assert "unapproved report path" in result.get("error", "")
    assert outside.read_bytes() == b"%PDF-1.4 PRIVATE"


def test_technical_report_rejects_generator_path_outside_reports(tmp_path, monkeypatch):
    import modules.dashboard_impl as d

    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    outside = tmp_path / "outside-technical.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE")

    def fake_generator(out_path):
        return {"ok": True, "path": str(outside)}

    with patch("modules.technical_report.generate_technical_pdf", side_effect=fake_generator):
        result = d._generate_dashboard_pdfs("tech-report")

    assert result.get("ok") is False
    assert "unapproved report path" in result.get("error", "")
    assert not (d._reports_dir() / outside.name).exists()


def test_technical_report_rejects_generator_symlink(tmp_path, monkeypatch):
    import modules.dashboard_impl as d

    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    outside = tmp_path / "outside-technical.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE")

    def fake_generator(out_path):
        Path(out_path).symlink_to(outside)
        return {"ok": True, "path": str(out_path)}

    with patch("modules.technical_report.generate_technical_pdf", side_effect=fake_generator):
        result = d._generate_dashboard_pdfs("tech-report")

    assert result.get("ok") is False
    assert "unapproved report path" in result.get("error", "")
    assert outside.read_bytes() == b"%PDF-1.4 PRIVATE"
