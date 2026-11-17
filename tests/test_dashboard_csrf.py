# © 2026 TrinTech Digital Defense — dashboard CSRF regression tests
from __future__ import annotations

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


def test_session_cookie_uses_https_when_secure_cookie_is_explicit():
    from modules.dashboard_impl import _Handler

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

        def _read_json_body(self):
            raise AssertionError("request body must not be processed after CSRF rejection")

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = (code, json.loads(body.decode("utf-8")))

    handler = Fake()
    handler.do_POST = dashboard._Handler.do_POST.__get__(handler, Fake)
    handler.do_POST()
    assert handler.sent == (403, {"ok": False, "error": "cross-origin request rejected"})
