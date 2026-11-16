# © 2026 TrinTech Digital Defense — authorized defensive use only
import pytest

from modules.central_agent import _maybe_ssl


def test_central_agent_tls_helper_fails_closed_without_certificate():
    with pytest.raises(RuntimeError, match="TLS certificate and key are required"):
        _maybe_ssl(object(), {"agent": {}})


def test_central_agent_tls_helper_rejects_partial_certificate_configuration():
    with pytest.raises(RuntimeError, match="requires both"):
        _maybe_ssl(object(), {"agent": {"tls_cert": "/tmp/cert.pem"}})



def test_network_listener_does_not_accept_legacy_shared_token(monkeypatch):
    from modules import central_agent

    class FakeRequest:
        allow_shared_token = False
        headers = {"X-Sentinel-Token": "legacy-shared-token"}

    monkeypatch.setattr(central_agent, "expected_token", lambda: "legacy-shared-token")
    assert central_agent.CentralAgentHandler._token_ok(FakeRequest()) is False
