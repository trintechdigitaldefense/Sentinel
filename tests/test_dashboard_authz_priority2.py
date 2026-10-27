# © 2026 TrinTech Digital Defense — Priority 2 dashboard authorization
from __future__ import annotations

import json
from unittest import mock

import pytest


def _handler(token="tok", allow_control=False, role="viewer", headers=None, path="/"):
    from modules.dashboard_impl import _Handler

    class H(_Handler):
        def __init__(self):
            self.token = token
            self.allow_control = allow_control
            self.headers = headers or {}
            self.path = path
            self.sent = None
            self.wfile = mock.Mock()

        def _send(self, code, body, ctype="application/json", extra_headers=None):
            self.sent = (code, body, ctype)

    return H()


def test_missing_token_401():
    h = _handler(headers={}, path="/api/status")
    assert h._auth_ok() is False


def test_invalid_bearer_401():
    h = _handler(headers={"Authorization": "Bearer wrong"}, path="/api/status")
    assert h._auth_ok() is False


def test_valid_bearer_ok():
    h = _handler(headers={"Authorization": "Bearer tok"}, path="/api/status")
    assert h._auth_ok() is True


def test_viewer_cannot_post_action(monkeypatch):
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": False, "role": "viewer", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)

    h = _handler(
        allow_control=False,
        headers={"Authorization": "Bearer tok"},
        path="/api/action",
    )
    h.do_POST = d._Handler.do_POST.__get__(h, type(h))
    h._read_json_body = lambda: {"action": "deception"}
    h.do_POST()
    assert h.sent is not None
    assert h.sent[0] == 403


def test_control_mode_enable_denied_when_false(monkeypatch):
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": False, "role": "viewer", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)
    monkeypatch.setattr(d, "_save_cfg", lambda c: None)

    h = _handler(allow_control=False, headers={"Authorization": "Bearer tok"}, path="/api/control-mode")
    h.do_POST = d._Handler.do_POST.__get__(h, type(h))
    h._read_json_body = lambda: {"allow_control": True}
    h.do_POST()
    assert h.sent[0] == 403
    body = json.loads(h.sent[1].decode())
    assert "cannot enable" in body.get("error", "").lower() or body.get("ok") is False


def test_unknown_action_rejected_when_control_on(monkeypatch):
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": True, "role": "admin", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)

    h = _handler(allow_control=True, headers={"Authorization": "Bearer tok"}, path="/api/action")
    h.do_POST = d._Handler.do_POST.__get__(h, type(h))
    h._read_json_body = lambda: {"action": "rm_rf_everything"}
    h.do_POST()
    assert h.sent is not None
    # unknown action should 400/403/not 200 success with ok true executing shell
    code = h.sent[0]
    body = h.sent[1]
    if code == 200:
        data = json.loads(body.decode())
        assert data.get("ok") is not True or "unknown" in str(data).lower() or "error" in data
    else:
        assert code in (400, 403, 404, 422)


def test_class_default_allow_control_false():
    from modules.dashboard_impl import _Handler
    assert _Handler.allow_control is False


def test_malformed_json_body_does_not_crash(monkeypatch):
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": True, "role": "admin", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)

    h = _handler(allow_control=True, headers={"Authorization": "Bearer tok"}, path="/api/action")
    h.do_POST = d._Handler.do_POST.__get__(h, type(h))
    h._read_json_body = lambda: {}  # empty action
    h.do_POST()
    assert h.sent is not None
