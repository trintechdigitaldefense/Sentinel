
from modules.firewall import drop_capabilities, backend, ensure_backend_ready, block_ip

def test_drop_capabilities_shape():
    c = drop_capabilities()
    assert "root" in c
    assert "backend" in c
    assert "real_drop" in c
    assert "tools" in c

def test_block_ip_dry_run_includes_caps():
    r = block_ip("203.0.113.50", confirm=False, reason="test")
    assert r.get("dry_run") is True
    assert "capabilities" in r or "hint" in r

def test_block_without_confirm_not_applied():
    r = block_ip("203.0.113.51", confirm=False)
    assert r.get("applied") is not True
