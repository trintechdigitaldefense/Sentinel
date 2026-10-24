# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Case → client-facing note templates (Phase 9).

Plain language for T&T SMB owners / managers — not SOC jargon dumps.
"""
from __future__ import annotations

from datetime import datetime


def render_client_note(case: dict, client_name: str = "Client") -> str:
    """Build a short client-ready note from a case record."""
    title = case.get("title") or "Security event"
    status = case.get("status") or "open"
    sev = case.get("severity") or "medium"
    cid = case.get("id") or ""
    summary = (case.get("summary") or "").strip()
    assignee = case.get("assignee") or "our security team"
    created = (case.get("created_at") or "")[:16].replace("T", " ")
    closed = (case.get("closed_at") or "")[:16].replace("T", " ")

    status_plain = {
        "new": "under initial review",
        "triaging": "being triaged by the team",
        "investigating": "under investigation",
        "contained": "contained; monitoring continues",
        "resolved": "resolved",
        "false_positive": "reviewed and closed as not a real threat",
    }.get(status, status)

    sev_plain = {
        "critical": "critical",
        "high": "high priority",
        "medium": "medium priority",
        "low": "low priority",
        "informational": "informational",
    }.get(sev, sev)

    lines = [
        f"Security update for {client_name}",
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Reference: {cid}",
        "",
        f"What we saw: {title}",
        f"Priority: {sev_plain}",
        f"Current status: {status_plain}",
    ]
    if summary:
        lines.append(f"Detail: {summary[:400]}")
    if created:
        lines.append(f"First recorded: {created}")
    if status in ("resolved", "false_positive") and closed:
        lines.append(f"Closed: {closed}")
    lines.append(f"Handled by: {assignee}")
    lines.append("")
    if status == "false_positive":
        lines.append(
            "This was reviewed and does not appear to be a real attack. "
            "No further action is required from your side."
        )
    elif status == "resolved":
        lines.append(
            "This matter is closed. We recommend keeping monitoring active "
            "and reviewing the next scheduled security summary."
        )
    elif status in ("contained", "investigating"):
        lines.append(
            "Please avoid major IT changes on affected systems until we confirm "
            "the situation is fully clear. Contact us if users report anything unusual."
        )
    else:
        lines.append(
            "Our monitoring is reviewing this. You do not need to take action "
            "unless we contact you with specific steps."
        )
    lines.append("")
    lines.append("— TrinTech Digital Defense (authorized monitoring)")
    return "\n".join(lines)


def client_note_for_case_id(case_id: str, client_name: str = "Client") -> dict:
    from modules import cases

    c = cases.get_case(case_id)
    if not c:
        return {"ok": False, "error": "case not found"}
    note = render_client_note(c, client_name=client_name)
    return {"ok": True, "case_id": case_id, "note": note}


def save_client_note(case_id: str, client_name: str = "Client") -> dict:
    """Render note, attach as case note, write file under data/client_notes/."""
    import os
    from pathlib import Path

    from modules import cases

    r = client_note_for_case_id(case_id, client_name=client_name)
    if not r.get("ok"):
        return r
    note = r["note"]
    cases.add_note(case_id, f"[client-template]\n{note}", author="client_notes")
    base = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data" / "client_notes"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{case_id}.txt"
    path.write_text(note)
    return {"ok": True, "case_id": case_id, "path": str(path), "note": note}
