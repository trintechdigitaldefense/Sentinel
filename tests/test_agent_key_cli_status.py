import json, subprocess, sys
from pathlib import Path

def test_agent_key_status_does_not_issue(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINEL_CENTRAL_DIR", str(tmp_path / "c"))
    eng = Path("sentinel.py").resolve()
    r = subprocess.run([sys.executable, str(eng), "agent-key", "status"], capture_output=True, text=True, timeout=60)
    # JSON object in stdout
    start = r.stdout.find("{")
    assert start >= 0, r.stdout
    # find last json-ish block
    data = json.loads(r.stdout[start:])
    assert "enrolled" in data
    assert "api_key" not in data
