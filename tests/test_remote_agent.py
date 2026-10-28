
from __future__ import annotations
from pathlib import Path

def test_build_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    from modules import remote_agent
    # reload paths
    import importlib
    importlib.reload(remote_agent)
    r = remote_agent.build_install_bundle(central_url="http://10.0.0.1:8743", label="t")
    assert r.get("ok")
    assert Path(r["install_script"]).is_file()
    text = Path(r["install_script"]).read_text()
    assert "SHARED_TOKEN" in text or "shared_token" in text
    assert "10.0.0.1:8743" in text

def test_register_checkin(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    from modules import remote_agent, network_fleet
    import importlib
    importlib.reload(remote_agent)
    importlib.reload(network_fleet)
    r = remote_agent.register_agent_checkin({
        "hostname": "office-pc",
        "ip": "192.168.1.50",
        "canaries": {"/tmp/a": {"canary_id": "1"}},
        "processes": [],
    })
    assert r.get("ok")
    agents = remote_agent.list_remote_agents()
    assert agents["count"] >= 1
