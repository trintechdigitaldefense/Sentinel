from modules.central_agent import CentralAgentHandler

def test_token_ok_accepts_shared(monkeypatch):
    class H(CentralAgentHandler):
        def __init__(self):
            self.headers = {"X-Sentinel-Token": "shared-secret-token-value"}
            self.client_address = ("127.0.0.1", 1)
    monkeypatch.setattr("modules.central_agent.expected_token", lambda: "shared-secret-token-value")
    assert H()._token_ok() is True

def test_token_ok_rejects_wrong(monkeypatch):
    class H(CentralAgentHandler):
        def __init__(self):
            self.headers = {"X-Sentinel-Token": "wrong"}
            self.client_address = ("127.0.0.1", 1)
    monkeypatch.setattr("modules.central_agent.expected_token", lambda: "shared-secret-token-value")
    assert H()._token_ok() is False

def test_token_ok_accepts_agent_key(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path))
    from modules.agent_keys import issue_key
    # issue needs master - read issue_key signature
    # issue_key(agent_id, master_key, provided_master)
    r = issue_key("agent-1", "master", "master")
    assert r.get("ok"), r
    key = r["api_key"]
    class H(CentralAgentHandler):
        def __init__(self):
            self.headers = {"X-Agent-Key": key}
            self.client_address = ("127.0.0.1", 1)
    monkeypatch.setattr("modules.central_agent.expected_token", lambda: "other-shared")
    assert H()._token_ok() is True
