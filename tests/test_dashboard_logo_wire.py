"""Logo asset and dashboard/PDF wiring."""
from __future__ import annotations

from pathlib import Path


def test_logo_asset_exists():
    from modules.dashboard_impl import _logo_asset
    p = _logo_asset()
    assert p is not None and p.is_file()
    assert p.read_bytes()[:4] == b"\x89PNG"


def test_html_includes_logo(monkeypatch, tmp_path):
    from modules.dashboard_impl import _html
    html = _html("tok123", {
        "control": True, "host": "h", "local_ip": "10.0.0.1", "version": "3",
        "ts": "2026-01-01", "siem": {}, "critical": {}, "ops": {}, "visibility": {},
        "hunt": {}, "firewall": {}, "config_flags": {}, "recent_alerts": [],
        "go_live": {}, "service": {}, "cases_open": [], "blocklist": {},
        "ssh_blocks": {}, "heartbeat": {},
    })
    assert "/api/assets/logo?token=tok123" in html
    assert "brand-logo" in html


def test_client_pdf_embeds_logo(tmp_path):
    from modules.client_report import generate_client_pdf
    out = tmp_path / "r.pdf"
    r = generate_client_pdf(out_path=out, client_name="T")
    assert r.get("ok"), r
    assert Path(r["path"]).read_bytes()[:4] == b"%PDF"
    assert r.get("logo")
