# © 2026 TrinTech Digital Defense — authorized defensive use only
"""End-to-end certificate validation and agent check-in tests."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def localhost_certificate(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is required to generate a disposable TLS test certificate")
    cert = tmp_path / "central.crt"
    key = tmp_path / "central.key"
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert, key


def test_agent_checkin_over_verified_https_and_rejects_untrusted_ca(
    tmp_path, monkeypatch, localhost_certificate
):
    cert, keyfile = localhost_certificate
    sentinel_home = tmp_path / "agent-home"
    central_home = tmp_path / "central-home"
    sentinel_home.mkdir()
    central_home.mkdir()
    monkeypatch.setenv("SENTINEL_DIR", str(sentinel_home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central_home))

    (sentinel_home / "config.json").write_text(json.dumps({
        "agent": {
            "bind": "127.0.0.1",
            "tls_cert": str(cert),
            "tls_key": str(keyfile),
        }
    }))

    import modules.agent_keys as agent_keys
    import modules.central_agent as central_agent
    import sentinel

    issued = agent_keys.issue_key("https-agent", "test-master", "test-master")
    assert issued["ok"] is True
    api_key = issued["api_key"]

    agent_config = {
        "agent": {
            "shared_token": api_key,
            "tls_ca": str(cert),
        }
    }
    monkeypatch.setattr(sentinel, "load_config_safe", lambda: agent_config)

    server = central_agent.start_central(port=0)
    port = server.server_address[1]
    central_url = f"https://127.0.0.1:{port}"
    payload = {
        "hostname": "https-agent",
        "ip": "192.0.2.40",
        "processes": [],
        "canaries": {},
    }
    try:
        assert sentinel.agent_report_to_central(central_url, payload, token=api_key) is True

        from modules.remote_agent import load_agents
        agents = load_agents()["agents"]
        assert agents["192.0.2.40"]["hostname"] == "https-agent"

        # A different self-signed certificate must not be accepted as the server CA.
        untrusted_cert = tmp_path / "untrusted.crt"
        untrusted_key = tmp_path / "untrusted.key"
        subprocess.run(
            [
                shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(untrusted_key), "-out", str(untrusted_cert), "-days", "1",
                "-subj", "/CN=untrusted",
                "-addext", "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        agent_config["agent"]["tls_ca"] = str(untrusted_cert)
        assert sentinel.agent_report_to_central(central_url, payload, token=api_key) is False
    finally:
        server.shutdown()
        server.server_close()


def test_agent_refuses_plain_http_to_non_loopback(monkeypatch):
    import sentinel

    monkeypatch.setattr(sentinel, "load_config_safe", lambda: {"agent": {"shared_token": "test"}})
    assert sentinel.agent_report_to_central(
        "http://central.example.test:8743", {"hostname": "test"}, token="test"
    ) is False
