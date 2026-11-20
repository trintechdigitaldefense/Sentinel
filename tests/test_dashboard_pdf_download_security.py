from pathlib import Path
from unittest.mock import patch

import modules.dashboard_impl as dashboard


class FakeHandler:
    path = "/api/report/download?name=Client_Report_test.pdf"
    token = "test-secret"
    allow_control = False
    secure_cookie = False

    def __init__(self):
        self.status = None
        self.body = b""
        self.content_type = None

    def _auth_ok(self):
        return False

    def _send(self, code, body, content_type="application/json", extra_headers=None):
        self.status = code
        self.body = body
        self.content_type = content_type


def test_pdf_download_rejects_unauthenticated_request(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))

    handler = FakeHandler()
    handler.do_GET = dashboard._Handler.do_GET.__get__(handler, FakeHandler)

    with patch.object(dashboard, "collect_full") as collect:
        handler.do_GET()

    assert handler.status == 401
    assert b"unauthorized" in handler.body
    collect.assert_not_called()


class AuthenticatedFakeHandler(FakeHandler):
    def _auth_ok(self):
        return True


def run_download(handler, monkeypatch, tmp_path, reports):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)

    monkeypatch.setattr(dashboard, "_reports_dir", lambda: reports)
    monkeypatch.setattr(dashboard, "_data", lambda: data)

    handler.do_GET = dashboard._Handler.do_GET.__get__(handler, type(handler))

    with patch.object(dashboard, "collect_full", return_value={}):
        handler.do_GET()

    return handler


def test_authenticated_pdf_download_serves_report(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    pdf = reports / "Client_Report_test.pdf"
    pdf.write_bytes(b"%PDF-1.4 test report")

    handler = AuthenticatedFakeHandler()
    handler.path = "/api/report/download?name=Client_Report_test.pdf"

    run_download(handler, monkeypatch, tmp_path, reports)

    assert handler.status == 200
    assert handler.body.startswith(b"%PDF")


def test_pdf_download_rejects_symlink_to_outside_file(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()

    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE OUTSIDE FILE")

    link = reports / "shadow.pdf"
    link.symlink_to(outside)

    handler = AuthenticatedFakeHandler()
    handler.path = "/api/report/download?name=shadow.pdf"

    run_download(handler, monkeypatch, tmp_path, reports)

    assert handler.status == 404
    assert b"PRIVATE OUTSIDE FILE" not in handler.body


def test_pdf_download_rejects_traversal_filename(monkeypatch, tmp_path):
    handler = AuthenticatedFakeHandler()
    handler.path = "/api/report/download?name=..%2Foutside.pdf"
    run_download(handler, monkeypatch, tmp_path, tmp_path / "reports")
    assert handler.status == 400


def test_pdf_download_rejects_symlink_in_data_directory(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"PRIVATE OUTSIDE FILE")
    (data / "shadow.pdf").symlink_to(outside)

    handler = AuthenticatedFakeHandler()
    handler.path = "/api/report/download?name=shadow.pdf"
    run_download(handler, monkeypatch, tmp_path, reports)

    assert handler.status == 404
    assert b"PRIVATE OUTSIDE FILE" not in handler.body


def test_pdf_download_rejects_directory_named_pdf(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "fake.pdf").mkdir()

    handler = AuthenticatedFakeHandler()
    handler.path = "/api/report/download?name=fake.pdf"
    run_download(handler, monkeypatch, tmp_path, reports)

    assert handler.status == 404


import importlib
import pytest


@pytest.mark.parametrize(
    "route,module_name,generator_name",
    [
        ("/api/report/pdf", "modules.client_report", "generate_client_pdf"),
        ("/api/report/tech", "modules.technical_report", "generate_technical_pdf"),
    ],
)
@pytest.mark.parametrize("scenario", ["legitimate", "outside", "symlink"])
def test_generated_pdf_endpoints_enforce_report_directory(
    monkeypatch, tmp_path, route, module_name, generator_name, scenario
):
    reports = tmp_path / "reports"
    reports.mkdir()
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.4 PRIVATE OUTSIDE FILE")

    module = importlib.import_module(module_name)

    def fake_generate(out_path, **kwargs):
        out_path = Path(out_path)
        if scenario == "legitimate":
            out_path.write_bytes(b"%PDF-1.4 legitimate report")
            result_path = out_path
        elif scenario == "outside":
            result_path = outside
        else:
            out_path.symlink_to(outside)
            result_path = out_path
        return {"ok": True, "path": str(result_path)}

    monkeypatch.setattr(dashboard, "_reports_dir", lambda: reports)
    monkeypatch.setattr(dashboard, "_data", lambda: tmp_path / "data")
    monkeypatch.setattr(dashboard, "_cfg", lambda: {})
    monkeypatch.setattr(
        module, generator_name, fake_generate
    )

    handler = AuthenticatedFakeHandler()
    handler.path = route
    handler.do_GET = dashboard._Handler.do_GET.__get__(handler, type(handler))

    with patch.object(dashboard, "collect_full", return_value={}):
        handler.do_GET()

    if scenario == "legitimate":
        assert handler.status == 200
        assert handler.body.startswith(b"%PDF")
        assert b"legitimate report" in handler.body
    else:
        assert handler.status in (404, 500)
        assert b"PRIVATE OUTSIDE FILE" not in handler.body


@pytest.mark.parametrize(
    "filename",
    [
        "bad%0d%0aX-Evil.pdf",
        'bad".pdf',
    ],
)
def test_pdf_download_rejects_unsafe_header_filename(
    monkeypatch, tmp_path, filename
):
    reports = tmp_path / "reports"
    reports.mkdir()
    handler = AuthenticatedFakeHandler()
    handler.path = f"/api/report/download?name={filename}"

    run_download(handler, monkeypatch, tmp_path, reports)

    assert handler.status == 400
