# © 2026 TrinTech Digital Defense — authorized defensive use only
import importlib
import os
import pytest
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



def test_corrupt_remote_config_and_registry_are_not_replaced(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "sentinel-home"))

    import importlib
    import modules.remote_agent as remote_agent

    importlib.reload(remote_agent)
    home = Path(remote_agent._home())
    home.mkdir(parents=True, exist_ok=True)
    config = home / "config.json"
    config.write_text("{broken")
    with pytest.raises(RuntimeError, match="refusing to replace"):
        remote_agent._cfg()
    assert config.read_text() == "{broken"

    registry = remote_agent.agents_registry_path()
    registry.write_text("{broken")
    with pytest.raises(RuntimeError, match="refusing to reset"):
        remote_agent.load_agents()
    assert registry.read_text() == "{broken"



def test_atomic_json_writers_produce_parseable_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "agent-home"))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central-home"))

    import importlib
    import json
    import modules.agent_keys as agent_keys
    import modules.remote_agent as remote_agent

    importlib.reload(agent_keys)
    importlib.reload(remote_agent)

    agent_keys._save({"agents": {"a": {"revoked": False}}})
    assert json.loads(agent_keys._keys_path().read_text())["agents"]["a"]["revoked"] is False

    remote_agent._save_cfg({"agent": {"enabled": True}})
    assert json.loads((remote_agent._home() / "config.json").read_text())["agent"]["enabled"] is True

    remote_agent.save_agents({"agents": {"host-a": {"last_seen": "now"}}})
    assert json.loads(remote_agent.agents_registry_path().read_text())["agents"]["host-a"]["last_seen"] == "now"
    assert (agent_keys._keys_path().stat().st_mode & 0o777) == 0o600
    assert (remote_agent._home() / "config.json").stat().st_mode & 0o777 == 0o600
    assert remote_agent.agents_registry_path().stat().st_mode & 0o777 == 0o600



def test_same_label_bundle_creation_uses_unique_directories_and_rotates_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "agent-home"))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central-home"))
    import importlib
    import modules.agent_keys as agent_keys
    import modules.remote_agent as remote_agent
    importlib.reload(agent_keys)
    importlib.reload(remote_agent)

    first = remote_agent.build_install_bundle(
        central_url="https://central.example.test:8443", label="repeat-agent"
    )
    first_key = Path(first["credential_file"]).read_text().strip()
    second = remote_agent.build_install_bundle(
        central_url="https://central.example.test:8443", label="repeat-agent"
    )
    second_key = Path(second["credential_file"]).read_text().strip()

    assert first["bundle_dir"] != second["bundle_dir"]
    assert first_key != second_key
    assert agent_keys.verify_key("repeat-agent", first_key) is False
    assert agent_keys.verify_key("repeat-agent", second_key) is True


def test_ssh_push_transfers_private_ca_bundle_file(tmp_path, monkeypatch):
    import subprocess
    import modules.remote_agent as remote_agent

    script = tmp_path / "install_agent.sh"
    key = tmp_path / "agent.key"
    ca = tmp_path / "central-ca.crt"
    for path in (script, key, ca):
        path.write_text("test")
    bundle = {
        "install_script": str(script),
        "credential_file": str(key),
        "ca_file": str(ca),
        "bundle_dir": str(tmp_path),
    }
    monkeypatch.setattr(remote_agent, "build_install_bundle", lambda **kwargs: bundle)
    monkeypatch.setattr(remote_agent.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(remote_agent.subprocess, "run", fake_run)
    result = remote_agent.push_via_ssh("operator@example.test")
    assert result["ok"] is True
    scp_call = next(command for command in calls if command[0] == "/usr/bin/scp")
    assert str(ca) in scp_call
    remote_command = calls[-1][-1]
    assert "central-ca.crt" in remote_command
    assert "chmod 644" in remote_command
