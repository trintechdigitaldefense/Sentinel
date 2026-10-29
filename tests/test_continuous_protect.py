
from __future__ import annotations

def test_continuous_protect_bootstrap_only():
    from modules.continuous_protect import run_continuous_protection
    r = run_continuous_protection(start_central=False, ensure_integrity=False, skip_hunt=True)
    assert r.get("ok") is True
    steps = r.get("steps") or {}
    assert "doctor" in steps
    assert "fleet" in steps
    assert "start" in steps
    assert "dashboard" in steps
    assert steps.get("hunt", {}).get("skipped") is True

def test_firewall_arm_runtime():
    from modules.firewall import arm_for_continuous, runtime_status
    arm = arm_for_continuous(apply_rules=True)
    assert arm.get("armed") is True
    rt = runtime_status()
    assert rt.get("running") is True
    assert rt.get("armed") is True

def test_always_on_status():
    from modules.always_on import status, stop
    st = status()
    assert "status" in st or "method" in st
