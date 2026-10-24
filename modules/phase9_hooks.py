# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Install Phase 9 hooks on import (false_positive → suppression)."""
from __future__ import annotations


def install() -> None:
    try:
        from modules import cases
    except Exception:
        return
    if getattr(cases.set_status, "_p9_hooked", False):
        return
    _orig = cases.set_status

    def set_status(case_id: str, status: str, actor: str = "operator"):
        r = _orig(case_id, status, actor=actor)
        if r.get("ok") and (status or "").strip().lower() == "false_positive":
            try:
                from modules.case_suppress import on_false_positive

                r["suppression"] = on_false_positive(case_id, actor=actor)
            except Exception as e:
                r["suppression"] = {"ok": False, "error": str(e)}
        return r

    set_status._p9_hooked = True  # type: ignore
    cases.set_status = set_status  # type: ignore


install()
