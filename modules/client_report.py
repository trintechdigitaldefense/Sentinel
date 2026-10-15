# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Plain-language PDF security report for non-technical clients."""
from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional


def _home() -> Path:
    import os
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    return _home() / "data"


def _cfg() -> dict:
    p = _home() / "config.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _load_status() -> dict:
    try:
        from modules.dashboard import collect_full
        return collect_full()
    except Exception as e:
        return {"error": str(e)}


def _plain_verdict(status: dict) -> tuple[str, str]:
    """Return (headline, explanation) in plain English."""
    hb = status.get("heartbeat") or {}
    alive = hb.get("alive") or (status.get("heartbeat_age_seconds") is not None and (status.get("heartbeat_age_seconds") or 9999) < 300)
    canaries = status.get("canaries") or {}
    if isinstance(canaries, dict):
        can_ok = canaries.get("alive", 0) or status.get("canaries_alive") or 0
        can_total = canaries.get("total", 0) or can_ok
    else:
        can_ok = int(status.get("canaries_alive") or canaries or 0)
        can_total = int(canaries or can_ok)
    drift = status.get("drift_score")
    alerts = status.get("alerts") or []
    open_alerts = len(alerts) if isinstance(alerts, list) else int(status.get("alerts_24h") or 0)

    if not alive and open_alerts > 5:
        return (
            "Attention needed",
            "Continuous monitoring may have stopped, and several security alerts are open. "
            "TrinTech should review this site promptly.",
        )
    if not alive:
        return (
            "Monitoring paused",
            "Protection tools are installed, but continuous monitoring is not currently running. "
            "Start the always-on service or contact TrinTech.",
        )
    if can_total and can_ok < can_total:
        return (
            "Possible intrusion activity",
            f"Some digital tripwires (canaries) were disturbed ({can_ok} of {can_total} intact). "
            "This can mean someone accessed sensitive-looking files. Investigation is recommended.",
        )
    if open_alerts > 10:
        return (
            "Elevated alert volume",
            f"About {open_alerts} recent security events were recorded. "
            "Most may be routine, but a review of the highest-priority items is recommended.",
        )
    if drift is not None and float(drift) < 90:
        return (
            "System changes detected",
            f"File integrity is at about {drift}% of the known-good baseline. "
            "Important system files may have changed. Confirm whether these changes were authorized.",
        )
    return (
        "All clear",
        "Continuous monitoring is active, digital tripwires are intact, and there are no critical open issues. "
        "Your network is under normal Sentinel protection.",
    )


def generate_client_pdf(out_path: Optional[Path] = None, client_name: Optional[str] = None) -> dict:
    """Generate a non-technical PDF report. Returns {ok, path, error?}."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, ListFlowable, ListItem
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return {"ok": False, "error": "reportlab not installed — run: pip install reportlab"}

    status = _load_status()
    cfg = _cfg()
    client = client_name or (cfg.get("dashboard") or {}).get("client_name") or cfg.get("client_name") or "Client"
    host = status.get("host") or socket.gethostname()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(out_path) if out_path else (_data() / f"Client_Report_{file_ts}.pdf")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    headline, explanation = _plain_verdict(status)
    hb = status.get("heartbeat") or {}
    age = status.get("heartbeat_age_seconds")
    if age is None and isinstance(hb, dict):
        age = hb.get("age_seconds")
    canaries = status.get("canaries") or {}
    if isinstance(canaries, dict):
        can_ok = canaries.get("alive", 0) or status.get("canaries_alive") or 0
        can_total = canaries.get("total", 0) or can_ok
    else:
        try:
            can_ok = int(status.get("canaries_alive") or canaries or 0)
            can_total = int(canaries or can_ok)
        except Exception:
            can_ok, can_total = 0, 0
    can_txt = f"{can_ok} of {can_total} intact"
    drift = status.get("drift_score")
    drift_txt = f"{drift}% intact" if drift is not None else "Baseline not yet measured"
    quiet = status.get("quiet") or (cfg.get("alerting") or {}).get("quiet_hours") or {}
    quiet_on = quiet.get("enabled") if isinstance(quiet, dict) else False
    alerts = status.get("alerts") or []
    if isinstance(alerts, list):
        recent = [str(a)[:120] for a in alerts[-8:]]
    else:
        recent = []

    # Friendly status rows
    mon = "Running" if (age is not None and age < 300) or hb.get("alive") else "Not running"
    rows = [
        ["What we checked", "Result (plain language)"],
        ["Continuous monitoring", mon + (f" (last signal {age}s ago)" if age is not None else "")],
        ["Digital tripwires (canaries)", can_txt],
        ["File integrity / drift", drift_txt],
        ["Quiet hours (alert pause)", "On — fewer alerts after hours" if quiet_on else "Off — full alerting"],
        ["Host protected", str(host)],
    ]

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Hero", fontSize=20, alignment=TA_CENTER, spaceAfter=4, textColor=colors.HexColor("#0B1F3A"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Sub", fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor("#64748B"), spaceAfter=10))
    styles.add(ParagraphStyle(name="H2", fontSize=12, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1A8CFF"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="BodyT", fontSize=10, leading=14, spaceAfter=6))
    styles.add(ParagraphStyle(name="Verdict", fontSize=14, alignment=TA_CENTER, spaceBefore=8, spaceAfter=6, textColor=colors.HexColor("#0F766E"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Foot", fontSize=8, textColor=colors.gray, alignment=TA_CENTER))

    if "Attention" in headline or "intrusion" in headline.lower() or "Elevated" in headline:
        styles["Verdict"].textColor = colors.HexColor("#B45309")
    if "paused" in headline.lower():
        styles["Verdict"].textColor = colors.HexColor("#B45309")

    story = []
    story.append(Paragraph("SENTINEL Security Snapshot", styles["Hero"]))
    story.append(Paragraph(f"Prepared for <b>{client}</b> · {ts}", styles["Sub"]))
    story.append(Paragraph("TrinTech Digital Defense · Confidential · Authorized use only", styles["Sub"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1A8CFF")))
    story.append(Paragraph(headline, styles["Verdict"]))
    story.append(Paragraph(explanation, styles["BodyT"]))
    story.append(Paragraph("At a glance", styles["H2"]))
    t = Table(rows, colWidths=[70 * mm, 100 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1F3A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    story.append(Paragraph("What Sentinel does for you", styles["H2"]))
    story.append(Paragraph(
        "Sentinel watches your network and computers around the clock. It looks for unknown devices, "
        "suspicious programs, and changes to important files. It also plants harmless 'canary' files that "
        "act like digital tripwires — if someone opens them, we are alerted.",
        styles["BodyT"],
    ))

    story.append(Paragraph("Recent activity (simplified)", styles["H2"]))
    if recent:
        for line in recent:
            # strip log noise for non-tech readers
            plain = line
            for noise in ("[INFO]", "[WARNING]", "[ERROR]", "\x1b[0m", "\x1b[91m", "\x1b[92m"):
                plain = plain.replace(noise, "")
            story.append(Paragraph(f"• {plain[:140]}", styles["BodyT"]))
    else:
        story.append(Paragraph("No notable recent alerts.", styles["BodyT"]))

    story.append(Paragraph("Recommended next steps", styles["H2"]))
    steps = [
        "Keep continuous monitoring running (always-on service or overnight hunt).",
        "If the verdict is not “All clear”, contact TrinTech Digital Defense for a guided review.",
        "Avoid deleting canary files or turning off quiet hours without checking with your security contact.",
        "Request a fresh report after any major IT change (new servers, staff laptops, or network gear).",
    ]
    for s in steps:
        story.append(Paragraph(f"• {s}", styles["BodyT"]))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(
        "This report is written for business owners and managers. Technical detail is available on request from TrinTech Digital Defense.",
        styles["Foot"],
    ))
    doc.build(story)
    return {"ok": True, "path": str(out_path), "headline": headline, "client": client}


if __name__ == "__main__":
    print(generate_client_pdf())
