
from modules.rbac import can_control, get_role

def test_viewer_no_control():
    cfg = {"dashboard": {"allow_control": False, "role": "admin"}}
    assert can_control(cfg) is False

def test_admin_with_control():
    cfg = {"dashboard": {"allow_control": True, "role": "admin"}}
    assert can_control(cfg) is True
    assert get_role(cfg) == "admin"

def test_viewer_role_blocks():
    cfg = {"dashboard": {"allow_control": True, "role": "viewer"}}
    assert can_control(cfg) is False
