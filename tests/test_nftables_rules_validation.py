from __future__ import annotations

import pytest

from modules import nftables_rules


def test_empty_deny_ports_does_not_restore_default_denials():
    rules = nftables_rules.build_ruleset(deny_ports=[])
    assert "sentinel-deny-" not in rules


def test_operator_ip_is_validated_before_ruleset_rendering():
    with pytest.raises(ValueError, match="invalid operator IP"):
        nftables_rules.build_ruleset(operator_ips=["127.0.0.1; flush ruleset"])


@pytest.mark.parametrize("entry", [
    (70000, "tcp"),
    (0, "tcp"),
    (22, "tcp; flush ruleset"),
    ("not-a-port", "udp"),
])
def test_deny_port_entries_are_validated(entry):
    with pytest.raises(ValueError):
        nftables_rules.build_ruleset(deny_ports=[entry])


def test_apply_returns_validation_error_without_invoking_nft(monkeypatch):
    monkeypatch.setattr(nftables_rules, "available", lambda: True)
    monkeypatch.setattr(nftables_rules, "is_root", lambda: True)

    def forbidden_run(*args, **kwargs):
        pytest.fail("nft must not run when user-controlled rule inputs are invalid")

    monkeypatch.setattr(nftables_rules, "_run", forbidden_run)
    result = nftables_rules.apply_base_ruleset(
        confirm=True, operator_ips=["192.0.2.1; flush ruleset"]
    )
    assert result["ok"] is False
    assert result["applied"] is False
    assert "invalid operator IP" in result["error"]


def test_add_and_remove_bad_hosts_reject_invalid_addresses(monkeypatch):
    monkeypatch.setattr(nftables_rules, "available", lambda: True)
    monkeypatch.setattr(nftables_rules, "is_root", lambda: True)
    monkeypatch.setattr(nftables_rules, "ensure_table", lambda: {"ok": True})
    assert nftables_rules.add_to_bad_hosts("192.0.2.1; flush ruleset")["ok"] is False
    assert nftables_rules.remove_from_bad_hosts("192.0.2.1; flush ruleset")["ok"] is False


def test_defense_pack_reports_partial_failure(monkeypatch):
    from modules import firewall

    monkeypatch.setattr(firewall, "ensure_base_chain", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(firewall, "protect_operator", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(firewall, "harden_ssh_port", lambda *args, **kwargs: {"ok": True})
    monkeypatch.setattr(firewall, "apply_profile", lambda *args, **kwargs: {"ok": False})
    monkeypatch.setattr(firewall, "deny_high_risk_ports", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(firewall, "rate_limit_ssh", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(firewall, "_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(firewall, "_case_event", lambda *args, **kwargs: None)

    result = firewall.apply_defense_pack(confirm=True)
    assert result["ok"] is False
    assert result["partial_apply"] is True
    assert result["steps"]["profile"] is False
