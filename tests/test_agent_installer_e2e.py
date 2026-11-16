# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Exercise the generated installer through a real HTTPS agent check-in.

The test uses a disposable local Git clone, isolated HOME/SENTINEL_DIR paths,
a short-lived test CA, and a real central listener. It never contacts a client.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.mark.skipif(
    not shutil.which("git") or not shutil.which("openssl"),
    reason="git and openssl are required for the installer-to-check-in test",
)
def test_generated_bundle_installs_and_checks_in_over_https(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    central_home = tmp_path / "central-home"
    central_keys = tmp_path / "central-keys"
    agent_user_home = tmp_path / "agent-user"
    agent_home = agent_user_home / ".sentinel"
    install_dir = tmp_path / "installed-sentinel"
    bundle_home = central_home
    for path in (central_home, central_keys, agent_user_home):
        path.mkdir(parents=True, exist_ok=True)

    cert = tmp_path / "central.crt"
    private_key = tmp_path / "central.key"
    subprocess.run(
        [
            shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-keyout", str(private_key), "-out", str(cert),
            "-days", "1", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True, capture_output=True, text=True,
    )

    central_config = {
        "agent": {
            "bind": "127.0.0.1",
            "tls_cert": str(cert),
            "tls_key": str(private_key),
        }
    }
    (central_home / "config.json").write_text(json.dumps(central_config))
    monkeypatch.setenv("SENTINEL_DIR", str(central_home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central_keys))

    from modules import central_agent
    from modules.remote_agent import build_install_bundle, load_agents

    server = central_agent.start_central(port=0)
    port = server.server_address[1]
    central_url = f"https://127.0.0.1:{port}"
    agent_id = "installer-e2e"

    # Create a disposable bare source so the generated script performs its
    # normal git clone path, pinned to the exact source tree under test.
    bare_repo = tmp_path / "sentinel-source.git"
    subprocess.run(
        ["git", "clone", "--bare", str(repo_root), str(bare_repo)],
        check=True, capture_output=True, text=True,
    )
    branch = "sentinel-installer-e2e"
    head = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "--git-dir", str(bare_repo), "update-ref", f"refs/heads/{branch}", head],
        check=True, capture_output=True, text=True,
    )

    process = None
    try:
        bundle = build_install_bundle(central_url=central_url, label=agent_id)
        script_path = Path(bundle["install_script"])
        assert bundle["ca_file"]
        assert Path(bundle["ca_file"]).is_file()
        assert Path(bundle["credential_file"]).stat().st_mode & 0o777 == 0o600
        assert script_path.stat().st_mode & 0o777 == 0o700

        env = os.environ.copy()
        env.update({
            "HOME": str(agent_user_home),
            "SENTINEL_DIR": str(agent_home),
            "SENTINEL_CENTRAL_DIR": str(central_keys),
            "INSTALL_DIR": str(install_dir),
            "REPO_URL": str(bare_repo),
            "BRANCH": branch,
            "PYTHON": sys.executable,
            "PYTHONUNBUFFERED": "1",
            "SENTINEL_FORCE_FOREGROUND": "1",
        })
        install_log = tmp_path / "agent-install.log"
        log_stream = install_log.open("w")
        process = subprocess.Popen(
            ["bash", str(script_path)],
            cwd=str(Path(bundle["bundle_dir"])),
            env=env,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            text=True,
        )

        deadline = time.monotonic() + 90
        recorded = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log_stream.flush()
                pytest.fail(f"generated installer/agent exited early ({process.returncode}):\\n{install_log.read_text()[-6000:]}")
            db_path = central_home / "data" / "remote_agents.json"
            if db_path.exists():
                try:
                    agents = json.loads(db_path.read_text()).get("agents", {})
                    recorded = any(v.get("hostname") for v in agents.values())
                except (OSError, ValueError):
                    recorded = False
            if recorded:
                break
            time.sleep(1)

        assert recorded, "installed agent did not check in to the central listener within 90 seconds"
        installed_config = json.loads((agent_home / "config.json").read_text())
        assert installed_config["agent"]["central_url"] == central_url
        assert installed_config["agent"]["tls_ca"] == str(agent_home / "central-ca.crt")
        assert (agent_home / "central-ca.crt").read_bytes() == cert.read_bytes()
        assert (agent_home / "config.json").stat().st_mode & 0o777 == 0o600
        assert load_agents()["agents"], "central agent registry did not record the check-in"
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if "log_stream" in locals():
            log_stream.close()
        server.shutdown()
        server.server_close()
