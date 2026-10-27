"""GET /api/report/pdf generates and returns a PDF without JS."""
from __future__ import annotations

from pathlib import Path

def test_generate_client_pdf_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    import importlib
    import modules.dashboard_impl as d
    importlib.reload(d)
    from modules.client_report import generate_client_pdf
    out = tmp_path / ".sentinel" / "data" / "reports" / "t.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    r = generate_client_pdf(out_path=out)
    assert r.get("ok"), r
    assert Path(r["path"]).read_bytes()[:4] == b"%PDF"
