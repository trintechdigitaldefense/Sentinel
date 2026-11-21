# © 2026 TrinTech Digital Defense — dashboard CSRF regression tests
from __future__ import annotations

import pytest

import json


class _Request:
    token = "csrf-test-token"
    secure_cookie = False

    def __init__(self, headers):
        self.headers = headers


def _cookie(origin="http://localhost:8792", host="localhost:8792"):
    return _Request({
        "Cookie": "sentinel_token=csrf-test-token",
        "Origin": origin,
        "Host": host,
    })


def test_session_cookie_requires_matching_same_origin():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie()) is True


def test_session_cookie_rejects_cross_origin_and_host_mismatch():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie("http://attacker.invalid", "localhost:8792")) is False
    assert _Handler._csrf_ok(_cookie("http://localhost:8792", "attacker.invalid")) is False


def test_session_cookie_rejects_missing_null_and_malformed_origin():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie(origin="")) is False
    assert _Handler._csrf_ok(_cookie(origin="null")) is False
    assert _Handler._csrf_ok(_cookie(origin="http://localhost:8792/path")) is False
    assert _Handler._csrf_ok(_cookie(origin="https://localhost:8792")) is False


def test_session_cookie_rejects_duplicate_origin_and_host_headers():
    from email.message import Message
    from modules.dashboard_impl import _Handler

    for duplicate_name in ("Origin", "Host"):
        headers = Message()
        headers.add_header("Cookie", "sentinel_token=csrf-test-token")
        headers.add_header("Origin", "http://localhost:8792")
        headers.add_header("Host", "localhost:8792")
        headers.add_header(duplicate_name, "http://attacker.invalid" if duplicate_name == "Origin" else "attacker.invalid")
        request = _Request(headers)
        assert _Handler._csrf_ok(request) is False


def test_session_cookie_rejects_origin_with_trailing_slash():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie(origin="http://localhost:8792/")) is False


def test_session_cookie_accepts_configured_ipv6_loopback(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("::1",))
    request = _cookie("http://[::1]:8792", "[::1]:8792")
    assert _Handler._csrf_ok(request) is True


def test_session_cookie_rejects_empty_query_and_fragment_delimiters():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie(origin="http://localhost:8792?")) is False
    assert _Handler._csrf_ok(_cookie(origin="http://localhost:8792#")) is False
    assert _Handler._csrf_ok(_cookie(host="localhost:8792?")) is False
    assert _Handler._csrf_ok(_cookie(host="localhost:8792#")) is False


def test_session_cookie_uses_https_when_secure_cookie_is_explicit(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.example",))
    request = _cookie("https://sentinel.example:8443", "sentinel.example:8443")
    request.secure_cookie = True
    assert _Handler._csrf_ok(request) is True
    request.headers["Origin"] = "http://sentinel.example:8443"
    assert _Handler._csrf_ok(request) is False


def test_bearer_authenticated_request_does_not_depend_on_cookie_origin():
    from modules.dashboard_impl import _Handler

    request = _Request({
        "Authorization": "Bearer csrf-test-token",
        "Cookie": "",
        "Origin": "https://attacker.invalid",
        "Host": "localhost:8792",
    })
    assert _Handler._csrf_ok(request) is True


def test_post_rejects_cross_origin_cookie_request_before_reading_body(monkeypatch):
    import modules.dashboard_impl as dashboard

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        allow_control = True
        headers = {
            "Cookie": "sentinel_token=csrf-test-token",
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
        }
        path = "/api/control-mode"
        sent = None

        def _auth_ok(self):
            return True

        def _csrf_ok(self):
            return dashboard._Handler._csrf_ok(self)

        def _read_json_body(self):
            raise AssertionError("request body must not be processed after CSRF rejection")

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = (code, json.loads(body.decode("utf-8")))

    handler = Fake()
    handler.do_POST = dashboard._Handler.do_POST.__get__(handler, Fake)
    handler.do_POST()
    assert handler.sent == (403, {"ok": False, "error": "cross-origin request rejected"})

def test_session_cookie_rejects_host_whitespace_and_port_mismatch():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie("http://localhost:8793", "localhost:8792")) is False
    assert _Handler._csrf_ok(_cookie("http://local host:8792", "local host:8792")) is False

def test_session_cookie_rejects_empty_and_zero_ports():
    from modules.dashboard_impl import _Handler

    assert _Handler._csrf_ok(_cookie("http://localhost:0", "localhost:0")) is False
    assert _Handler._csrf_ok(_cookie("http://localhost:", "localhost:")) is False


def test_session_cookie_rejects_untrusted_host_even_when_origin_matches(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("localhost", "127.0.0.1"))
    request = _cookie("http://attacker.invalid:8792", "attacker.invalid:8792")
    assert _Handler._csrf_ok(request) is False


def test_session_cookie_accepts_configured_remote_hostname(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.customer.com",))
    request = _cookie("https://sentinel.customer.com", "sentinel.customer.com")
    request.secure_cookie = True
    assert _Handler._csrf_ok(request) is True


def test_session_cookie_rejects_remote_hostname_not_in_allowlist(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.customer.com",))
    request = _cookie("https://attacker.invalid", "attacker.invalid")
    request.secure_cookie = True
    assert _Handler._csrf_ok(request) is False


def test_login_rejects_cross_origin_before_reading_body_or_setting_cookie():
    import modules.dashboard_impl as dashboard

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        headers = {
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
            "Content-Length": "32",
        }
        path = "/api/session"
        sent = None
        cookie_set = False

        def _origin_host_ok(self):
            return dashboard._Handler._origin_host_ok(self)

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = (code, json.loads(body.decode("utf-8")))
            if extra_headers and "Set-Cookie" in extra_headers:
                self.cookie_set = True

        @property
        def rfile(self):
            raise AssertionError("rejected login must not read the request body")

    handler = Fake()
    handler.do_POST = dashboard._Handler.do_POST.__get__(handler, Fake)
    handler.do_POST()

    assert handler.sent == (
        403,
        {"ok": False, "error": "cross-origin request rejected"},
    )
    assert handler.cookie_set is False


def test_reverse_proxy_forwarded_headers_cannot_override_origin_host_validation(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.customer.com",))
    request = _cookie(
        "https://attacker.invalid",
        "attacker.invalid",
    )
    request.secure_cookie = True
    request.headers["X-Forwarded-Host"] = "sentinel.customer.com"
    request.headers["X-Forwarded-Proto"] = "https"

    assert _Handler._csrf_ok(request) is False


def test_reverse_proxy_accepts_public_origin_and_preserved_host(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.customer.com",))
    request = _cookie(
        "https://sentinel.customer.com",
        "sentinel.customer.com",
    )
    request.secure_cookie = True
    request.headers["X-Forwarded-Proto"] = "http"
    request.headers["X-Forwarded-Host"] = "internal-backend"

    assert _Handler._csrf_ok(request) is True


def test_cross_origin_control_mode_post_does_not_mutate_state():
    import modules.dashboard_impl as dashboard

    protected_state = {"mode": "monitor", "save_count": 0}

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        allow_control = True
        headers = {
            "Cookie": "sentinel_token=csrf-test-token",
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
            "Content-Length": "20",
        }
        path = "/api/control-mode"
        sent = None

        def _auth_ok(self):
            return True

        def _csrf_ok(self):
            return dashboard._Handler._csrf_ok(self)

        def _origin_host_ok(self):
            return dashboard._Handler._origin_host_ok(self)

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = code

        def _cfg(self):
            raise AssertionError("rejected request must not access configuration")

        def _save_cfg(self, cfg):
            protected_state["save_count"] += 1

        def _read_json_body(self):
            raise AssertionError("rejected request must not read the body")

    handler = Fake()
    handler.do_POST = dashboard._Handler.do_POST.__get__(handler, Fake)
    handler.do_POST()

    assert handler.sent == 403
    assert protected_state == {"mode": "monitor", "save_count": 0}


def test_cross_origin_quiet_action_post_does_not_mutate_config():
    import modules.dashboard_impl as dashboard

    protected_state = {
        "quiet_mode": False,
        "quiet_hours_enabled": False,
        "save_count": 0,
    }

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        allow_control = True
        headers = {
            "Cookie": "sentinel_token=csrf-test-token",
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
            "Content-Length": "20",
        }
        path = "/api/action"
        sent = None

        def _auth_ok(self):
            return True

        def _csrf_ok(self):
            return dashboard._Handler._csrf_ok(self)

        def _origin_host_ok(self):
            return dashboard._Handler._origin_host_ok(self)

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = code

        def _read_json_body(self):
            raise AssertionError("rejected request must not read the body")

    def forbidden_config_access():
        raise AssertionError("rejected request must not access configuration")

    original_cfg = dashboard._cfg
    original_save_cfg = dashboard._save_cfg
    dashboard._cfg = forbidden_config_access
    dashboard._save_cfg = lambda cfg: protected_state.update(save_count=protected_state["save_count"] + 1)
    try:
        handler = Fake()
        handler.do_POST = dashboard._Handler.do_POST.__get__(handler, Fake)
        handler.do_POST()
    finally:
        dashboard._cfg = original_cfg
        dashboard._save_cfg = original_save_cfg

    assert handler.sent == 403
    assert protected_state == {
        "quiet_mode": False,
        "quiet_hours_enabled": False,
        "save_count": 0,
    }


def test_session_cookie_rejects_trailing_dot_trusted_hostname(monkeypatch):
    from modules.dashboard_impl import _Handler

    monkeypatch.setattr(_Handler, "trusted_hosts", ("sentinel.customer.com",))
    request = _cookie(
        "https://sentinel.customer.com.",
        "sentinel.customer.com.",
    )
    request.secure_cookie = True
    assert _Handler._csrf_ok(request) is False

@pytest.mark.parametrize(
    "route",
    [
        "/api/report/pdf",
        "/api/report/client",
        "/api/report/generate",
        "/api/report/tech",
        "/api/report/technical",
    ],
)
def test_report_generation_get_rejected_before_collection(monkeypatch, tmp_path, route):
    import modules.dashboard_impl as dashboard
    from modules.dashboard_impl import _Handler

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        trusted_hosts = ("localhost", "127.0.0.1")
        allow_control = False
        path = route
        headers = {
            "Cookie": "sentinel_token=csrf-test-token",
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
        }

        def _auth_ok(self):
            return _Handler._auth_ok(self)

        def _csrf_ok(self):
            return _Handler._csrf_ok(self)

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = code
            self.body = body

    handler = Fake()
    handler.do_GET = _Handler.do_GET.__get__(handler, Fake)
    reports = tmp_path / "reports"
    monkeypatch.setattr(dashboard, "_reports_dir", lambda: reports)

    def forbidden_collection():
        raise AssertionError("rejected report request must not collect dashboard data")

    monkeypatch.setattr(dashboard, "collect_full", forbidden_collection)
    handler.do_GET()

    assert handler.sent == 405
    assert b"method not allowed" in handler.body
    assert not reports.exists()


@pytest.mark.parametrize("route", ["/api/realtime?scan=1", "/api/threats?scan=1"])
def test_realtime_scan_get_rejected_before_collection(monkeypatch, route):
    import modules.dashboard_impl as dashboard
    from modules.dashboard_impl import _Handler

    class Fake:
        token = "csrf-test-token"
        secure_cookie = False
        trusted_hosts = ("localhost", "127.0.0.1")
        allow_control = False
        path = route
        headers = {
            "Cookie": "sentinel_token=csrf-test-token",
            "Origin": "http://attacker.invalid",
            "Host": "localhost:8792",
        }

        def _auth_ok(self):
            return _Handler._auth_ok(self)

        def _csrf_ok(self):
            return _Handler._csrf_ok(self)

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = code
            self.body = body

    handler = Fake()
    handler.do_GET = _Handler.do_GET.__get__(handler, Fake)

    def forbidden_collection():
        raise AssertionError("rejected realtime scan must not collect dashboard data")

    monkeypatch.setattr(dashboard, "collect_full", forbidden_collection)
    handler.do_GET()

    assert handler.sent == 405
    assert b"method not allowed" in handler.body
