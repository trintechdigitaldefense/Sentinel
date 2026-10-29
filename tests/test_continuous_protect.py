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
