from __future__ import annotations
from pathlib import Path

def test_technical_pdf_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    from modules.technical_report import generate_technical_pdf
    out = tmp_path / "t.pdf"
    r = generate_technical_pdf(out_path=out)
    assert r.get("ok"), r
    assert Path(r["path"]).read_bytes()[:4] == b"%PDF"

def test_client_pdf_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    from modules.client_report import generate_client_pdf
    out = tmp_path / "c.pdf"
    r = generate_client_pdf(out_path=out, client_name="T")
    assert r.get("ok"), r
    assert Path(r["path"]).read_bytes()[:4] == b"%PDF"

def test_generate_dashboard_pdfs_both(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    # dashboard_impl reads home .sentinel - set env is enough for technical/client modules
    from modules.dashboard_impl import _generate_dashboard_pdfs
    r = _generate_dashboard_pdfs("pdf-report")
    assert r.get("ok"), r
    assert len(r.get("downloads") or []) >= 1

def test_collect_version_not_stale():
    from modules.dashboard_impl import collect_full
    from sentinel import __version__
    d = collect_full()
    assert d.get("version") == __version__
    assert "canaries" in d
