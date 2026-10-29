from modules.phase5 import heartbeat_write
from modules.always_on import status

def test_status_ok_when_heartbeat_alive(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # heartbeat_write uses SENTINEL_DIR via phase5 _data
    heartbeat_write({"source": "test"})
    st = status()
    assert st.get("heartbeat_alive") is True
    assert st.get("ok") is True
