# © 2026 TrinTech Digital Defense — authorized defensive use only
import pytest

from modules.central_agent import _maybe_ssl


def test_central_agent_tls_helper_fails_closed_without_certificate():
    with pytest.raises(RuntimeError, match="TLS certificate and key are required"):
        _maybe_ssl(object(), {"agent": {}})


def test_central_agent_tls_helper_rejects_partial_certificate_configuration():
    with pytest.raises(RuntimeError, match="requires both"):
        _maybe_ssl(object(), {"agent": {"tls_cert": "/tmp/cert.pem"}})
