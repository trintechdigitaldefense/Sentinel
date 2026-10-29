
from modules.brute_force import parse_failures, check, progressive_duration, status

SAMPLE = """
sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[2]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[3]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[4]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[5]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[6]: Failed password for root from 203.0.113.10 port 22 ssh2
sshd[7]: Invalid user admin from 198.51.100.20
sshd[8]: pam_unix(sshd:auth): authentication failure; rhost=198.51.100.20
"""

def test_parse_failures_counts():
    f = parse_failures(SAMPLE)
    assert f.get("203.0.113.10", 0) >= 5
    assert f.get("198.51.100.20", 0) >= 1

def test_check_candidates_no_autoblock(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # force parse by monkeypatching collect
    import modules.brute_force as bf
    monkeypatch.setattr(bf, "_collect_auth_text", lambda ssh=None: SAMPLE)
    cfg = {"ssh_blocking": {"active": True, "auto_block": False, "max_failures": 5}}
    r = check(config=cfg)
    assert r["ok"]
    assert r["blocked_count"] == 0
    ips = [c["ip"] for c in r["candidates"]]
    assert "203.0.113.10" in ips

def test_progressive(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    assert progressive_duration("9.9.9.9", 100, {"max_block_duration": 10000, "repeat_multiplier": 2}) == 100
    assert progressive_duration("9.9.9.9", 100, {"max_block_duration": 10000, "repeat_multiplier": 2}) == 200

def test_status_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    s = status()
    assert "config" in s
    assert "auto_block" in s["config"]
