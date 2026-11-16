# © 2026 TrinTech Digital Defense — authorized defensive use only
import importlib
import os
from pathlib import Path


def test_bundle_uses_per_agent_secret_sidecar(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "agent-home"))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central-home"))

    import modules.agent_keys as agent_keys
    import modules.remote_agent as remote_agent

    importlib.reload(agent_keys)
    importlib.reload(remote_agent)

    bundle = remote_agent.build_install_bundle(
        central_url="https://central.example.test:8443",
        label="office-agent",
    )
    script = Path(bundle["install_script"])
    secret = Path(bundle["credential_file"])

    assert script.exists()
    assert secret.exists()
    assert secret.read_text().strip()
    assert secret.read_text().strip() not in script.read_text()
    assert "SHARED_TOKEN=\"$(< \"$TOKEN_FILE\")\"" in script.read_text()
    assert "http://" not in script.read_text()
    assert (script.stat().st_mode & 0o777) == 0o700
    assert (secret.stat().st_mode & 0o777) == 0o600
    assert (script.parent.stat().st_mode & 0o777) == 0o700


def test_bundle_rejects_non_tls_remote_url(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "agent-home"))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central-home"))

    import importlib
    import modules.agent_keys as agent_keys
    import modules.remote_agent as remote_agent

    importlib.reload(agent_keys)
    importlib.reload(remote_agent)

    import pytest
    with pytest.raises(ValueError, match="require HTTPS"):
        remote_agent.build_install_bundle(
            central_url="http://central.example.test:8743",
            label="office-agent",
        )
