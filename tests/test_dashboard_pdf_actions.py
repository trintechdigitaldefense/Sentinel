
"""Dashboard PDF generator unit smoke (no HTTP server)."""
from pathlib import Path
from modules.dashboard_impl import _generate_dashboard_pdfs

def test_generate_client_pdf(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = _generate_dashboard_pdfs("client-report")
    assert r.get("ok"), r
    assert r.get("path")
    assert Path(r["path"]).is_file()
    assert Path(r["path"]).read_bytes()[:4] == b"%PDF"

def test_generate_tech_pdf(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = _generate_dashboard_pdfs("tech-report")
    assert r.get("ok"), r
    assert Path(r["path"]).is_file()
