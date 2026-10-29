from modules.suppressions import add_suppression, is_suppressed, save, load

def test_is_suppressed_matches_details(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # reset rules by saving empty then add
    save([])
    add_suppression("suspicious_process", "backup-script", note="test")
    ev = {"type": "SUSPICIOUS_PROCESS", "details": {"command": "/usr/local/bin/backup-script --full"}}
    assert is_suppressed(ev) is True
    ev2 = {"type": "SUSPICIOUS_PROCESS", "details": {"command": "totally-other"}}
    assert is_suppressed(ev2) is False
