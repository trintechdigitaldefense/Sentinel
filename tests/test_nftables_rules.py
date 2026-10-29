
from modules.nftables_rules import build_ruleset, apply_base_ruleset, available

def test_build_ruleset_contains_sets_and_basics():
    text = build_ruleset(operator_ips=["192.168.1.10"], ssh_port=22)
    assert "table inet sentinel" in text
    assert "bad_hosts" in text
    assert "ct state established,related accept" in text
    assert "iif \"lo\" accept" in text or 'iif "lo" accept' in text
    assert "192.168.1.10" in text
    assert "tcp dport 22" in text

def test_apply_dry_run():
    r = apply_base_ruleset(confirm=False)
    assert r.get("dry_run") is True or r.get("error")
