# © 2026 TrinTech Digital Defense — authorized defensive use only
import pytest

from modules.central_agent import _maybe_ssl


def test_central_agent_tls_helper_fails_closed_without_certificate():
    with pytest.raises(RuntimeError, match="TLS certificate and key are required"):
        _maybe_ssl(object(), {"agent": {}})


def test_central_agent_tls_helper_rejects_partial_certificate_configuration():
    with pytest.raises(RuntimeError, match="requires both"):
        _maybe_ssl(object(), {"agent": {"tls_cert": "/tmp/cert.pem"}})



def test_network_listener_does_not_accept_legacy_shared_token(tmp_path, monkeypatch):
    import importlib
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path))
    import modules.agent_keys as agent_keys
    importlib.reload(agent_keys)
    from modules import central_agent

    class FakeRequest:
        allow_shared_token = False
        headers = {"X-Sentinel-Token": "legacy-shared-token"}

    monkeypatch.setattr(central_agent, "expected_token", lambda: "legacy-shared-token")
    assert central_agent.CentralAgentHandler._token_ok(FakeRequest()) is False


def test_handler_auth_policy_is_isolated_per_listener():
    from modules.central_agent import (
        CentralAgentHandler,
        _handler_for_listener,
    )

    loopback_handler = _handler_for_listener(True)
    network_handler = _handler_for_listener(False)
    assert loopback_handler is not network_handler
    assert loopback_handler.allow_shared_token is True
    assert network_handler.allow_shared_token is False
    assert CentralAgentHandler.allow_shared_token is False
