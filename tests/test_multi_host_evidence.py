
from modules.multi_host import status, prepare_fleet
from modules.field_evidence import collect

def test_multi_host_status_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    st = status()
    assert "registry_agents" in st
    assert "hints" in st
    assert "ok" in st

def test_field_evidence_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # seed a heartbeat file
    data = tmp_path / "data"
    data.mkdir(parents=True)
    (data / "heartbeat.json").write_text('{"alive": true}')
    r = collect(include_soak=False)
    assert r.get("ok")
    assert r.get("zip")
    assert r.get("sha256")
    from pathlib import Path
    assert Path(r["zip"]).exists()
