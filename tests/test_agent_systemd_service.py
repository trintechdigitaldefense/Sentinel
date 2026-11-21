# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Exercise the generated agent installer under a real systemd manager."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


SYSTEMD_TEST = (
    os.environ.get("SENTINEL_SYSTEMD_TEST") == "1"
    and os.geteuid() == 0
    and Path("/run/systemd/system").exists()
    and shutil.which("systemctl")
)


def _systemctl(*args, check=True):
    return subprocess.run(
        ["systemctl", *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
    )


def _wait_for_checkin(registry, previous=None, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if registry.exists():
            try:
                agents = json.loads(registry.read_text()).get("agents", {})
                for entry in agents.values():
                    seen = entry.get("last_seen")
                    if seen and seen != previous:
                        return seen
            except (OSError, ValueError):
                pass
        time.sleep(0.5)
    pytest.fail("systemd-managed agent did not produce a fresh central check-in")


@pytest.mark.skipif(not SYSTEMD_TEST, reason="requires disposable root VM/container booted with systemd as PID 1")
def test_generated_agent_service_install_restart_stop_and_start(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    test_root = Path(tempfile.mkdtemp(prefix="sentinel-systemd-", dir="/home"))
    central_home = test_root / "central-home"
    central_keys = test_root / "central-keys"
    agent_user_home = test_root / "agent-user"
    agent_home = agent_user_home / "custom-sentinel-data"
    install_dir = test_root / "installed-sentinel"
    for path in (central_home, central_keys, agent_user_home):
        path.mkdir(parents=True, exist_ok=True)

    cert = test_root / "central.crt"
    private_key = test_root / "central.key"
    subprocess.run(
        [
            shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-keyout", str(private_key), "-out", str(cert),
            "-days", "1", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True, capture_output=True, text=True,
    )
    (central_home / "config.json").write_text(json.dumps({
        "agent": {"bind": "127.0.0.1", "tls_cert": str(cert), "tls_key": str(private_key)}
    }))
    monkeypatch.setenv("SENTINEL_DIR", str(central_home))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(central_keys))

    from modules import central_agent
    from modules.remote_agent import build_install_bundle

    server = central_agent.start_central(port=0)
    service = "sentinel-agent.service"
    unit_path = Path("/etc/systemd/system") / service
    try:
        port = server.server_address[1]
        bundle = build_install_bundle(
            central_url=f"https://127.0.0.1:{port}",
            label="systemd-installer-e2e",
        )
        source_tree = test_root / "sentinel-source"
        shutil.copytree(
            repo_root,
            source_tree,
            ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".venv"),
        )
        subprocess.run(["git", "-C", str(source_tree), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(source_tree), "config", "user.name", "Sentinel CI"], check=True)
        subprocess.run(["git", "-C", str(source_tree), "config", "user.email", "sentinel-ci@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(source_tree), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(source_tree), "commit", "-qm", "Disposable systemd test source"], check=True)

        bare_repo = test_root / "sentinel-source.git"
        subprocess.run(
            ["git", "clone", "--bare", str(source_tree), str(bare_repo)],
            check=True, capture_output=True, text=True,
        )
        branch = "sentinel-systemd-e2e"
        head = subprocess.run(
            ["git", "-C", str(source_tree), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "--git-dir", str(bare_repo), "update-ref", f"refs/heads/{branch}", head],
            check=True, capture_output=True, text=True,
        )

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
        })
        result = subprocess.run(
            ["bash", bundle["install_script"]],
            cwd=bundle["bundle_dir"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + "\n" + result.stderr
        assert unit_path.exists(), "installer did not create sentinel-agent.service"
        _systemctl("is-active", "--quiet", service)
        assert _systemctl("show", "-p", "NoNewPrivileges", "--value", service).stdout.strip() == "yes"
        assert _systemctl("show", "-p", "ProtectSystem", "--value", service).stdout.strip() == "full"
        assert _systemctl("show", "-p", "PrivateTmp", "--value", service).stdout.strip() == "no"
        assert f"PYTHON={sys.executable}" in _systemctl("show", "-p", "Environment", "--value", service).stdout
        first_pid = int(_systemctl("show", "-p", "MainPID", "--value", service).stdout.strip())
        assert first_pid > 0
        registry = central_home / "data" / "remote_agents.json"
        first_seen = _wait_for_checkin(registry)

        # Kill the managed process to prove Restart=on-failure recovers it.
        _systemctl("kill", "--signal=SIGKILL", service)
        recovery_deadline = time.monotonic() + 30
        recovered_pid = 0
        while time.monotonic() < recovery_deadline:
            active = _systemctl("is-active", service, check=False).stdout.strip()
            pid_text = _systemctl("show", "-p", "MainPID", "--value", service, check=False).stdout.strip()
            if active == "active" and pid_text.isdigit() and int(pid_text) > 0 and int(pid_text) != first_pid:
                recovered_pid = int(pid_text)
                break
            time.sleep(0.5)
        assert recovered_pid > 0, "systemd did not restart the agent after SIGKILL"
        first_seen = _wait_for_checkin(registry, previous=first_seen)
        first_pid = recovered_pid

        # Verify explicit systemd restart and fresh process startup/check-in.
        _systemctl("restart", service)
        _systemctl("is-active", "--quiet", service)
        second_pid = int(_systemctl("show", "-p", "MainPID", "--value", service).stdout.strip())
        assert second_pid > 0
        second_seen = _wait_for_checkin(registry, previous=first_seen)

        _systemctl("stop", service)
        assert _systemctl("is-active", service, check=False).stdout.strip() == "inactive"
        _systemctl("start", service)
        _systemctl("is-active", "--quiet", service)
        assert int(_systemctl("show", "-p", "MainPID", "--value", service).stdout.strip()) > 0
        _wait_for_checkin(registry, previous=second_seen)
    finally:
        _systemctl("disable", "--now", service, check=False)
        if unit_path.exists():
            unit_path.unlink()
        _systemctl("daemon-reload", check=False)
        server.shutdown()
        server.server_close()
        shutil.rmtree(test_root, ignore_errors=True)
