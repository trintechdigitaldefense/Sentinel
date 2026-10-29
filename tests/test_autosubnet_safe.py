from modules.phase5 import detect_local_subnets, auto_subnet_apply
from modules.subnet_guard import is_too_wide

def test_detect_returns_safe_cidrs():
    nets = detect_local_subnets()
    assert nets
    for n in nets:
        assert not is_too_wide(n)

def test_auto_subnet_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DIR", str(tmp_path))
    # phase5 _cfg may use home - still should return ok structure
    r = auto_subnet_apply(config={"network": {}})
    assert r.get("ok") is True
    assert r.get("scan_subnets")
