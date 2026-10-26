# © 2026 TrinTech Digital Defense — defensive unit tests
"""Dashboard control-mode must not escalate with token alone."""
from __future__ import annotations

import json
from pathlib import Path
from unittest import mock


def test_handler_class_default_allow_control_false():
    from modules.dashboard_impl import _Handler
    assert _Handler.allow_control is False


def test_control_mode_cannot_enable_when_config_false(tmp_path, monkeypatch):
    """POST control-mode allow_control=true must 403 if config has allow_control false."""
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": False, "role": "viewer", "token": "test-token-xyz"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)
    saved = {}

    def fake_save(c):
        saved.update(c)

    monkeypatch.setattr(d, "_save_cfg", fake_save)

    class Fake:
        allow_control = False
        token = "test-token-xyz"
        headers = {"Authorization": "Bearer test-token-xyz"}
        path = "/api/control-mode"
        rfile = None
        sent = None

        def _auth_ok(self):
            return True

        def _read_json_body(self):
            return {"allow_control": True}

        def _send(self, code, body, ctype="application/json"):
            self.sent = (code, body)

    h = Fake()
    # Bind methods from real handler
    h.do_POST = d._Handler.do_POST.__get__(h, Fake)
    h.do_POST()
    assert h.sent is not None
    code, body = h.sent
    assert code == 403
    data = json.loads(body.decode())
    assert data.get("ok") is False


def test_control_mode_can_disable_when_enabled(monkeypatch):
    """Turning controls OFF with token is allowed (fail-safe)."""
    import json
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": True, "role": "admin", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)
    monkeypatch.setattr(d, "_save_cfg", lambda c: None)

    class Fake:
        allow_control = True
        token = "tok"
        headers = {}
        path = "/api/control-mode"
        sent = None

        def _auth_ok(self):
            return True

        def _read_json_body(self):
            return {"allow_control": False}

        def _send(self, code, body, ctype="application/json"):
            self.sent = (code, body)

    h = Fake()
    h.do_POST = d._Handler.do_POST.__get__(h, Fake)
    h.do_POST()
    assert h.sent[0] == 200
    data = json.loads(h.sent[1].decode())
    assert data.get("allow_control") is False


def test_post_action_denied_when_view_only(monkeypatch):
    import modules.dashboard_impl as d

    cfg = {"dashboard": {"allow_control": False, "role": "viewer", "token": "tok"}}
    monkeypatch.setattr(d, "_cfg", lambda: cfg)

    class Fake:
        allow_control = False
        token = "tok"
        headers = {}
        path = "/api/action"
        sent = None

        def _auth_ok(self):
            return True

        def _read_json_body(self):
            return {"action": "deception"}

        def _send(self, code, body, ctype="application/json"):
            self.sent = (code, body)

    h = Fake()
    h.do_POST = d._Handler.do_POST.__get__(h, Fake)
    h.do_POST()
    # Should hit view-only 403 before action runs
    assert h.sent is not None
    assert h.sent[0] == 403
