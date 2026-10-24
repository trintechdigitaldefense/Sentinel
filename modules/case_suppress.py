# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Link false_positive cases to suppressions (Phase 9)."""
from __future__ import annotations


def suppression_from_case(case: dict, note: str = "") -> dict:
    """Create a suppression rule derived from a false_positive case."""
    from modules import suppressions

    title = (case.get("title") or "").strip()
    source = (case.get("source") or "case").strip()
    cid = case.get("id") or ""
    pattern = title[:120] if title else cid
    detection_type = source.replace("sentinel_engine", "canary").replace(" ", "_")[:40] or "generic"
    rule = suppressions.add_suppression(
        detection_type=detection_type,
        pattern=pattern,
        host="*",
        note=note or f"auto from false_positive case {cid}",
    )
    try:
        rules = suppressions.load()
        for r in rules:
            if r.get("id") == rule.get("id"):
                r["case_id"] = cid
                break
        suppressions.save(rules)
    except Exception:
        pass
    return rule


def on_false_positive(case_id: str, actor: str = "operator") -> dict:
    """After status → false_positive, add suppression and audit note."""
    from modules import cases

    c = cases.get_case(case_id)
    if not c:
        return {"ok": False, "error": "case not found"}
    if c.get("status") != "false_positive":
        return {"ok": False, "error": "case is not false_positive"}
    rule = suppression_from_case(c)
    try:
        cases.add_note(
            case_id,
            f"Suppression {rule.get('id')} created from false_positive "
            f"(pattern={rule.get('pattern')!r}).",
            author=actor,
        )
    except Exception:
        pass
    return {"ok": True, "case_id": case_id, "suppression": rule}
