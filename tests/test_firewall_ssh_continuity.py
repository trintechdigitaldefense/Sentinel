# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Real SSH-session continuity test in a disposable network namespace."""
import os
import select
import shutil
import subprocess
import time
from pathlib import Path

import pytest


REQUIRED = ("ip", "nft", "ssh", "sshd", "ssh-keygen")


def _run(*args, check=True, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)


def _read_echo(stream, expected, timeout=8):
    ready, _, _ = select.select([stream], [], [], timeout)
    assert ready, f"SSH session did not return {expected!r} within {timeout}s"
    line = stream.readline().decode("utf-8", errors="replace").strip()
    assert line == expected, f"expected SSH echo {expected!r}, got {line!r}"


@pytest.mark.skipif(
    os.environ.get("SENTINEL_ISOLATED_SSH_TEST") != "1"
    or os.geteuid() != 0
    or any(not shutil.which(cmd) for cmd in REQUIRED),
    reason="requires the dedicated root SSH/nftables CI VM",
)
def test_live_ssh_session_survives_firewall_apply_reapply_and_rollback(tmp_path, monkeypatch):
    from modules import nftables_rules as rules

    namespace = "sentinel-ssh-test"
    host_if = "stssh0"
    peer_if = "stcli0"
    host_ip = "198.18.0.1"
    client_ip = "198.18.0.2"
    ssh_port = "22222"
    sshd = None
    client = None
    created_ns = False

    # This runner is an ephemeral GitHub-hosted VM. The client is isolated in
    # its own network namespace and reaches sshd over a veth pair.
    try:
        _run("ip", "netns", "add", namespace)
        created_ns = True
        _run("ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if)
        _run("ip", "link", "set", peer_if, "netns", namespace)
        _run("ip", "addr", "add", f"{host_ip}/30", "dev", host_if)
        _run("ip", "link", "set", host_if, "up")
        _run("ip", "-n", namespace, "addr", "add", f"{client_ip}/30", "dev", peer_if)
        _run("ip", "-n", namespace, "link", "set", "lo", "up")
        _run("ip", "-n", namespace, "link", "set", peer_if, "up")

        key = tmp_path / "client_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True, capture_output=True, text=True,
        )
        authorized = tmp_path / "authorized_keys"
        authorized.write_text(key.with_suffix(".pub").read_text())
        authorized.chmod(0o600)
        host_key = tmp_path / "host_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
            check=True, capture_output=True, text=True,
        )
        config = tmp_path / "sshd_config"
        config.write_text("\n".join([
            f"Port {ssh_port}",
            f"ListenAddress {host_ip}",
            f"HostKey {host_key}",
            f"PidFile {tmp_path / 'sshd.pid'}",
            f"AuthorizedKeysFile {authorized}",
            "PermitRootLogin yes",
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "UsePAM no",
            "StrictModes no",
            "AllowUsers root",
            "LogLevel VERBOSE",
        ]) + "\n")
        Path("/run/sshd").mkdir(parents=True, exist_ok=True)
        _run(shutil.which("sshd"), "-t", "-f", str(config))
        sshd_log = tmp_path / "sshd.log"
        sshd_log_stream = sshd_log.open("w")
        sshd = subprocess.Popen(
            [shutil.which("sshd"), "-D", "-e", "-f", str(config)],
            stdout=sshd_log_stream,
            stderr=subprocess.STDOUT,
        )

        # Wait for the SSH listener before establishing the persistent session.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            probe = _run("ip", "netns", "exec", namespace, "ssh", "-i", str(key),
                         "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                         "-o", "UserKnownHostsFile=/dev/null", "-p", ssh_port,
                         f"root@{host_ip}", "true", check=False, timeout=3)
            if probe.returncode == 0:
                break
            time.sleep(0.25)
        else:
            sshd_log_stream.flush()
            diag = _run("ip", "addr", "show", "dev", host_if, check=False).stdout
            peer_diag = _run("ip", "-n", namespace, "addr", "show", check=False).stdout
            verbose = _run("ip", "netns", "exec", namespace, "ssh", "-vvv", "-i", str(key),
                           "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                           "-o", "UserKnownHostsFile=/dev/null", "-p", ssh_port,
                           f"root@{host_ip}", "true", check=False, timeout=5)
            pytest.fail(
                "temporary sshd was unreachable before firewall changes; "
                f"sshd_poll={sshd.poll()}\\nsshd_log={sshd_log.read_text()}\\n"
                f"host_link={diag}\\nclient_link={peer_diag}\\nssh_debug={verbose.stderr[-5000:]}"
            )

        client = subprocess.Popen(
            ["ip", "netns", "exec", namespace, "ssh", "-T", "-i", str(key),
             "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ServerAliveInterval=2",
             "-o", "ServerAliveCountMax=3", "-p", ssh_port, f"root@{host_ip}", "cat"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
        )
        assert client.stdin is not None and client.stdout is not None
        client.stdin.write(b"before-firewall\n")
        client.stdin.flush()
        _read_echo(client.stdout, "before-firewall")

        baseline = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=[client_ip], deny_ports=[]
        )
        assert baseline.get("ok") is True, baseline
        client.stdin.write(b"after-apply\n")
        client.stdin.flush()
        _read_echo(client.stdout, "after-apply")

        reapplied = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=[client_ip], deny_ports=[]
        )
        assert reapplied.get("ok") is True, reapplied
        client.stdin.write(b"after-reapply\n")
        client.stdin.flush()
        _read_echo(client.stdout, "after-reapply")

        # Force only the post-apply verification read to fail. The production
        # rollback path must restore the prior Sentinel table while the same
        # already-established SSH TCP session remains interactive.
        original_run = rules._run
        list_calls = {"count": 0}

        def fail_verification(cmd, timeout=30):
            if cmd[:5] == ["nft", "list", "table", "inet", "sentinel"]:
                list_calls["count"] += 1
                if list_calls["count"] == 2:
                    return {
                        "ok": False, "code": 1, "stdout": "",
                        "stderr": "simulated verification failure", "cmd": cmd,
                    }
            return original_run(cmd, timeout=timeout)

        monkeypatch.setattr(rules, "_run", fail_verification)
        rolled_back = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=[client_ip], deny_ports=[]
        )
        assert rolled_back.get("ok") is False, rolled_back
        assert rolled_back.get("rollback_ok") is True, rolled_back
        client.stdin.write(b"after-rollback\n")
        client.stdin.flush()
        _read_echo(client.stdout, "after-rollback")
    finally:
        if client is not None:
            client.terminate()
            try:
                client.wait(timeout=5)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=3)
        if sshd is not None:
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=3)
        if "sshd_log_stream" in locals():
            sshd_log_stream.close()
        _run("nft", "delete", "table", "inet", "sentinel", check=False)
        _run("ip", "link", "delete", host_if, check=False)
        if created_ns:
            _run("ip", "netns", "delete", namespace, check=False)
