
def test_issue_local_agent_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "central"))
    from modules.agent_enroll_ux import issue_local_agent_key, enroll_status
    r = issue_local_agent_key("site-a")
    assert r.get("ok"), r
    assert r.get("api_key")
    st = enroll_status()
    assert st.get("ok") is True
