# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Live nftables checks. These tests run only inside the dedicated CI container."""
import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SENTINEL_ISOLATED_NFT_TEST") != "1"
    or not shutil.which("nft")
    or os.geteuid() != 0,
    reason="requires the explicitly isolated, root nftables CI container",
)


def _nft(*args):
    return subprocess.run(
        ["nft", *args], capture_output=True, text=True, check=False, timeout=15
    )


def _delete_table(name):
    _nft("delete", "table", "inet", name)


def test_live_apply_ipv4_ipv6_sets_and_preserves_unrelated_tables():
    from modules import nftables_rules as rules

    _delete_table("sentinel")
    _delete_table("sentinel_unrelated")
    try:
        assert _nft("add", "table", "inet", "sentinel_unrelated").returncode == 0
        applied = rules.apply_base_ruleset(
            confirm=True,
            rate_limit_ssh=False,
            operator_ips=["127.0.0.1", "::1"],
            deny_ports=[],
        )
        assert applied["ok"] is True, applied
        assert applied["verify_ok"] is True

        assert rules.add_to_bad_hosts("192.0.2.40")["ok"] is True
        assert rules.add_to_bad_hosts("2001:db8::40")["ok"] is True

        listed = _nft("list", "table", "inet", "sentinel")
        assert listed.returncode == 0, listed.stderr
        assert "127.0.0.1" in listed.stdout
        assert "::1" in listed.stdout
        assert "bad_hosts" in listed.stdout
        assert "bad_hosts6" in listed.stdout
        assert "192.0.2.40" in listed.stdout
        assert "2001:db8::40" in listed.stdout

        # Re-apply must replace only Sentinel's table and leave other tables intact.
        reapplied = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=["127.0.0.1"], deny_ports=[]
        )
        assert reapplied["ok"] is True, reapplied
        unrelated = _nft("list", "table", "inet", "sentinel_unrelated")
        assert unrelated.returncode == 0, unrelated.stderr
    finally:
        _delete_table("sentinel")
        _delete_table("sentinel_unrelated")


def test_live_verification_failure_restores_previous_sentinel_table(monkeypatch):
    from modules import nftables_rules as rules

    _delete_table("sentinel")
    try:
        baseline = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=["127.0.0.1"], deny_ports=[]
        )
        assert baseline["ok"] is True, baseline
        original_run = rules._run
        list_calls = {"count": 0}

        def fail_one_verification(cmd, timeout=30):
            if cmd[:5] == ["nft", "list", "table", "inet", "sentinel"]:
                list_calls["count"] += 1
                if list_calls["count"] == 2:
                    return {
                        "ok": False, "code": 1, "stdout": "",
                        "stderr": "simulated verification failure", "cmd": cmd,
                    }
            return original_run(cmd, timeout=timeout)

        monkeypatch.setattr(rules, "_run", fail_one_verification)
        result = rules.apply_base_ruleset(
            confirm=True, rate_limit_ssh=False, operator_ips=["192.0.2.99"], deny_ports=[]
        )
        assert result["ok"] is False
        assert result["rollback_ok"] is True, result

        restored = original_run(["nft", "list", "table", "inet", "sentinel"])
        assert restored["ok"] is True, restored
        assert "127.0.0.1" in restored["stdout"]
        assert "192.0.2.99" not in restored["stdout"]
    finally:
        _delete_table("sentinel")
