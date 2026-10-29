
from modules.subnet_guard import is_too_wide, filter_safe_subnets

def test_wide_subnets_rejected():
    assert is_too_wide("10.0.0.0/8")
    assert is_too_wide("172.16.0.0/12")
    assert is_too_wide("0.0.0.0/0")

def test_office_slash24_ok():
    assert not is_too_wide("192.168.1.0/24")
    assert not is_too_wide("10.10.0.0/16")

def test_filter_drops_wide():
    assert filter_safe_subnets(["10.0.0.0/8", "192.168.5.0/24"]) == ["192.168.5.0/24"]
    assert filter_safe_subnets([]) == ["192.168.1.0/24"]
