# © 2026 TrinTech Digital Defense — authorized defensive use only
from modules.agent_keys import issue_key, verify_key, revoke, list_agents
from modules.backup_restore import backup, restore
from modules.smb_canary import deploy_smb_canary, check_smb_canaries
from modules.rbac import hash_password, verify_password, can_control, get_role


def test_agent_keys_issue_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central"))
    r = issue_key("site1", "master", "master")
    assert r["ok"] and r["api_key"]
    assert verify_key("site1", r["api_key"])
    assert revoke("site1", "master", "master")["ok"]
    assert not verify_key("site1", r["api_key"])


def test_backup_restore(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / "sent"))
    d = tmp_path / "sent"
    (d / "data").mkdir(parents=True)
    (d / "config.json").write_text('{"client_name":"t"}')
    (d / "data" / "alerts.log").write_text("{}\n")
    out = tmp_path / "b.enc"
    assert backup(str(out), "pw")["ok"]
    # wipe and restore
    (d / "config.json").unlink()
    assert restore(str(out), "pw", force=True)["ok"]
    assert (d / "config.json").exists()


def test_smb_canary(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    r = deploy_smb_canary()
    assert r["ok"] and r["files"] >= 4
    assert check_smb_canaries() == []


def test_rbac():
    h = hash_password("secret")
    assert verify_password("secret", h)
    assert not verify_password("wrong", h)
    assert can_control({"dashboard": {"role": "admin", "allow_control": True}})
    assert not can_control({"dashboard": {"role": "viewer", "allow_control": True}})
    assert get_role({"dashboard": {"role": "viewer"}}) == "viewer"
