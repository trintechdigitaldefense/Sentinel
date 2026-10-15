# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.response_actions import kill_process, block_ip, disable_user


def test_disabled_by_default():
    assert kill_process(99999, {"enabled": False, "kill_process": True})["ok"] is False
    assert block_ip("1.2.3.4", {"enabled": False, "block_ip": True})["ok"] is False
    assert disable_user("bob", {"enabled": False, "disable_user": True})["ok"] is False


def test_enabled_flag_required_per_action():
    cfg = {"enabled": True, "kill_process": False, "block_ip": False, "disable_user": False}
    assert "disabled" in kill_process(1, cfg).get("error", "")
    assert "disabled" in block_ip("8.8.8.8", cfg).get("error", "")


def test_refuse_root_disable():
    cfg = {"enabled": True, "disable_user": True}
    r = disable_user("root", cfg)
    assert r["ok"] is False
