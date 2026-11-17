# © 2026 TrinTech Digital Defense — dashboard TLS deployment tests
from __future__ import annotations

import pytest


@pytest.mark.parametrize("requested", ["0.0.0.0", "::", "*", "192.0.2.10", "10.0.0.5"])
def test_dashboard_backend_refuses_non_loopback_bind(requested):
    from modules.dashboard_impl import _safe_dashboard_bind

    assert _safe_dashboard_bind(requested) == "127.0.0.1"


@pytest.mark.parametrize("requested", ["127.0.0.1"])
def test_dashboard_backend_allows_loopback_bind(requested):
    from modules.dashboard_impl import _safe_dashboard_bind

    assert _safe_dashboard_bind(requested) == requested


def test_remote_dashboard_requires_secure_cookie():
    from modules.dashboard_impl import _validate_remote_dashboard_config

    with pytest.raises(RuntimeError, match="cookie_secure=true"):
        _validate_remote_dashboard_config({"remote_access": True, "cookie_secure": False})


def test_remote_dashboard_accepts_explicit_secure_cookie():
    from modules.dashboard_impl import _validate_remote_dashboard_config

    _validate_remote_dashboard_config({"remote_access": True, "cookie_secure": True})


def test_remote_dashboard_rejects_ambiguous_string_booleans():
    from modules.dashboard_impl import _validate_remote_dashboard_config

    with pytest.raises(RuntimeError, match="must be a boolean"):
        _validate_remote_dashboard_config({"remote_access": "true", "cookie_secure": "true"})


def test_local_dashboard_does_not_require_secure_cookie():
    from modules.dashboard_impl import _validate_remote_dashboard_config

    _validate_remote_dashboard_config({"remote_access": False, "cookie_secure": False})
