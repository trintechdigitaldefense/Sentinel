
from __future__ import annotations

def test_rate_allow():
    from modules.central_agent import rate_allow, _rate, _rate_lock
    with _rate_lock:
        _rate.clear()
    assert rate_allow("10.0.0.9") is True
    # flood
    ok = True
    for _ in range(200):
        ok = rate_allow("10.0.0.8")
    assert ok is False

def test_stale_and_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path / ".sentinel"))
    import importlib
    import modules.central_agent as ca
    import modules.remote_agent as ra
    importlib.reload(ra)
    importlib.reload(ca)
    ra.register_agent_checkin({"hostname": "h1", "ip": "10.1.1.1", "canaries": {"a": {}}, "processes": []})
    st = ca.list_stale_agents(max_age_minutes=15)
    assert st["ok"] and st["live"] >= 1
    summary = ca.central_status_summary()
    assert summary.get("ok") is True

def test_start_central_import():
    from modules.central_agent import start_central, CentralAgentHandler
    assert hasattr(CentralAgentHandler, "do_POST")
    assert callable(start_central)
