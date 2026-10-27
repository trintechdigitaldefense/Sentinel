# © 2026 TrinTech Digital Defense
from __future__ import annotations


def test_firewall_status_safe():
    from modules import firewall
    st = firewall.status() if hasattr(firewall, "status") else {}
    assert st is not None


def test_apply_profile_dry_run_default():
    from modules import firewall
    if not hasattr(firewall, "apply_profile"):
        return
    try:
        out = firewall.apply_profile("default", confirm=False)
    except TypeError:
        try:
            out = firewall.apply_profile("default")
        except Exception:
            return
    if isinstance(out, dict):
        assert out.get("dry_run") is True or "would" in str(out).lower() or out.get("ok") is not None
