# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Plain-language PDF security report for non-technical clients.

Enhanced layout: cover bar, status cards, protection checklist,
categorized activity, clear next steps, and honest disclaimers.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


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


def _canary_counts(status: dict) -> tuple[int, int]:
    canaries = status.get("canaries") or {}
    if isinstance(canaries, dict):
        ok = int(canaries.get("alive") or status.get("canaries_alive") or 0)
        total = int(canaries.get("total") or ok or 0)
        return ok, total
    try:
        n = int(canaries)
        return n, n
    except Exception:
        return 0, 0


def _alert_count(status: dict) -> int:
    alerts = status.get("alerts") or status.get("recent_alerts") or []
    if isinstance(alerts, list):
        return len(alerts)
    try:
        return int(status.get("alerts_24h") or 0)
    except Exception:
        return 0


def _heartbeat_ok(status: dict) -> bool:
    hb = status.get("heartbeat") or {}
    if isinstance(hb, dict) and hb.get("alive"):
        return True
    age = status.get("heartbeat_age_seconds")
    if age is None and isinstance(hb, dict):
        age = hb.get("age_seconds")
    try:
        return age is not None and float(age) < 300
    except Exception:
        return False


def _plain_verdict(status: dict) -> tuple[str, str, str]:
    """Return (headline, explanation, level) where level is green|amber|red."""
    alive = _heartbeat_ok(status)
    can_ok, can_total = _canary_counts(status)
    open_alerts = _alert_count(status)
    crit = status.get("critical") or {}
    open_crit = len(crit.get("open") or []) if isinstance(crit, dict) else 0
    drift = status.get("drift_score")
    go = status.get("go_live") or {}
    ready = str((go.get("ready") if isinstance(go, dict) else "") or status.get("go_live_ready") or "").upper()

    if open_crit > 0:
        return (
            "Critical issues open",
            f"{open_crit} critical alert(s) still need an operator acknowledgement. "
            "TrinTech should review these before treating the site as clear.",
            "red",
        )
    if not alive and open_alerts > 5:
        return (
            "Attention needed",
            "Continuous monitoring may have stopped, and several security alerts are open. "
            "TrinTech should review this site promptly.",
            "red",
        )
    if not alive:
        return (
            "Monitoring paused",
            "Protection tools are installed, but continuous monitoring is not currently running. "
            "Start the always-on service or contact TrinTech.",
            "amber",
        )
    if can_total and can_ok < can_total:
        return (
            "Possible intrusion activity",
            f"Some digital tripwires (canaries) were disturbed ({can_ok} of {can_total} intact). "
            "This can mean someone accessed sensitive-looking files. Investigation is recommended.",
            "red",
        )
    if open_alerts > 25:
        return (
            "Elevated alert volume",
            f"About {open_alerts} recent security events were recorded. "
            "Many may be routine baseline noise; a guided review of the highest-priority items is recommended.",
            "amber",
        )
    if open_alerts > 10:
        return (
            "Elevated alert volume",
            f"About {open_alerts} recent security events were recorded. "
            "Most may be routine, but a review of the highest-priority items is recommended.",
            "amber",
        )
    if drift is not None:
        try:
            if float(drift) < 90:
                return (
                    "System changes detected",
                    f"File integrity is at about {float(drift):.0f}% of the known-good baseline. "
                    "Important system files may have changed. Confirm whether these changes were authorized.",
                    "amber",
                )
        except Exception:
            pass
    if ready and ready not in ("OK", "READY", "PASS", "FULL", ""):
        if ready in ("PARTIAL", "WARN"):
            return (
                "Protection partially ready",
                "Most defenses are in place, but go-live still reports a partial status. "
                "Finish remaining setup steps (service, baselines, or alert channel) with TrinTech.",
                "amber",
            )
    return (
        "All clear",
        "Continuous monitoring is active, digital tripwires are intact, and there are no critical open issues. "
        "Your network is under normal Sentinel protection.",
        "green",
    )


def _protection_rows(status: dict) -> list[tuple[str, str, str]]:
    """List of (name, status_label, note)."""
    rows = []
    alive = _heartbeat_ok(status)
    rows.append((
        "Continuous monitoring",
        "Running" if alive else "Not running",
        "Heartbeat from the hunt/service loop" if alive else "Start service-install or hunt",
    ))
    can_ok, can_total = _canary_counts(status)
    if can_total:
        rows.append((
            "Canary tripwires",
            f"{can_ok}/{can_total} intact",
            "Harmless decoy files that alert if touched",
        ))
    else:
        rows.append(("Canary tripwires", "Not deployed", "Run deception / go-live to plant canaries"))

    fim = status.get("fim") or status.get("integrity") or {}
    if isinstance(fim, dict) and (fim.get("baseline") or fim.get("files")):
        n = fim.get("files") or fim.get("count") or "yes"
        rows.append(("File integrity (FIM)", "Baseline active", f"Tracking {n} paths" if n != "yes" else "Baseline present"))
    else:
        # try go_live flags
        gl = status.get("go_live") or {}
        steps = (gl.get("steps") if isinstance(gl, dict) else None) or {}
        if isinstance(steps, dict) and steps.get("fim_baseline") in ("ok", "OK", True):
            rows.append(("File integrity (FIM)", "Baseline active", "Known-good file snapshot in place"))
        else:
            rows.append(("File integrity (FIM)", "Check recommended", "Run integrity / go-live"))

    svc = status.get("service") or {}
    if isinstance(svc, dict):
        active = svc.get("active") or svc.get("running")
        rows.append((
            "Always-on service",
            "Installed" if active else "Not installed",
            "Survives logout / reboot when installed",
        ))
    else:
        rows.append(("Always-on service", "Unknown", "Check service-status"))

    fw = status.get("firewall") or {}
    if isinstance(fw, dict) and fw:
        backend = fw.get("backend") or "host"
        rows.append(("Host firewall", str(backend), "Host control plane — not a perimeter appliance"))
    else:
        rows.append(("Host firewall", "Available", "Dry-run by default until you apply rules"))

    crit = status.get("critical") or {}
    open_crit = len(crit.get("open") or []) if isinstance(crit, dict) else 0
    rows.append((
        "Critical alerts",
        "None open" if open_crit == 0 else f"{open_crit} open",
        "Critical items stay open until acknowledged",
    ))

    n_alerts = _alert_count(status)
    rows.append(("Recent alerts", str(n_alerts), "Includes baseline learning noise on first runs"))
    return rows


def _simplify_alert_line(item: Any) -> str:
    if isinstance(item, dict):
        t = item.get("type") or item.get("event") or item.get("title") or "Event"
        d = item.get("detail") or item.get("message") or item.get("cmd") or ""
        if isinstance(d, dict):
            d = json.dumps(d, default=str)[:100]
        return f"{t}: {str(d)[:120]}"
    plain = str(item)
    for noise in ("[INFO]", "[WARNING]", "[ERROR]", "\x1b[0m", "\x1b[91m", "\x1b[92m", "\x1b[94m", "\x1b[1m"):
        plain = plain.replace(noise, "")
    return plain.strip()[:160]


def _categorize_recent(status: dict) -> dict[str, list[str]]:
    buckets = {
        "Needs attention": [],
        "Baseline / routine": [],
        "Other": [],
    }
    recent = status.get("recent_alerts") or status.get("alerts") or []
    if not isinstance(recent, list):
        return buckets
    attention_keys = (
        "REVERSE_SHELL", "CANARY", "LD_PRELOAD", "CRITICAL", "SELF_INTEGRITY",
        "TAMPER", "BRUTE", "SSH_BLOCK", "RANSOM", "WEB_SHELL",
    )
    routine_keys = (
        "NEW_SUID", "NEW_PERSISTENCE", "NEW_CRON", "RC_FILE", "FIM_MODIFIED",
        "REMOVED_PERSISTENCE", "systemd",
    )
    for item in recent[:40]:
        line = _simplify_alert_line(item)
        up = line.upper()
        if any(k in up for k in attention_keys):
            buckets["Needs attention"].append(line)
        elif any(k in up for k in routine_keys):
            buckets["Baseline / routine"].append(line)
        else:
            buckets["Other"].append(line)
    return buckets


def generate_client_pdf(out_path: Optional[Path] = None, client_name: Optional[str] = None) -> dict:
    """Generate an enhanced non-technical PDF report. Returns {ok, path, error?}."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return {"ok": False, "error": "reportlab not installed — run: pip install reportlab"}

    status = _load_status()
    cfg = _cfg()
    client = (
        client_name
        or (cfg.get("dashboard") or {}).get("client_name")
        or cfg.get("client_name")
        or "Client"
    )
    host = status.get("host") or socket.gethostname()
    ip = status.get("ip") or status.get("local_ip") or "—"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(out_path) if out_path else (_data() / "reports" / f"Client_Report_{file_ts}.pdf")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    headline, explanation, level = _plain_verdict(status)
    level_colors = {
        "green": colors.HexColor("#1B7F4E"),
        "amber": colors.HexColor("#B8860B"),
        "red": colors.HexColor("#B00020"),
    }
    accent = level_colors.get(level, colors.HexColor("#0E7C7B"))
    navy = colors.HexColor("#0B1F3A")
    teal = colors.HexColor("#0E7C7B")
    light = colors.HexColor("#F4F6F8")
    muted = colors.HexColor("#64748B")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle", fontName="Helvetica-Bold", fontSize=18,
        textColor=colors.white, alignment=TA_CENTER, spaceAfter=4, leading=22,
    ))
    styles.add(ParagraphStyle(
        name="CoverSub", fontName="Helvetica", fontSize=10,
        textColor=colors.HexColor("#E2E8F0"), alignment=TA_CENTER, spaceAfter=2, leading=13,
    ))
    styles.add(ParagraphStyle(
        name="H2", fontName="Helvetica-Bold", fontSize=12,
        textColor=navy, spaceBefore=12, spaceAfter=6, leading=15,
    ))
    styles.add(ParagraphStyle(
        name="BodyT", fontName="Helvetica", fontSize=9.5,
        textColor=colors.HexColor("#1E293B"), leading=13, spaceAfter=4, alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="Verdict", fontName="Helvetica-Bold", fontSize=14,
        textColor=accent, alignment=TA_CENTER, spaceBefore=6, spaceAfter=4, leading=18,
    ))
    styles.add(ParagraphStyle(
        name="VerdictBody", fontName="Helvetica", fontSize=10,
        textColor=colors.HexColor("#334155"), alignment=TA_CENTER, leading=13, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Foot", fontName="Helvetica", fontSize=8,
        textColor=muted, leading=10, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="Cell", fontName="Helvetica", fontSize=8.5, leading=11, textColor=colors.HexColor("#1E293B"),
    ))
    styles.add(ParagraphStyle(
        name="CellBold", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=navy,
    ))
    styles.add(ParagraphStyle(
        name="SmallCenter", fontName="Helvetica", fontSize=8,
        textColor=muted, alignment=TA_CENTER, leading=10,
    ))

    story = []

    # Cover banner table
    banner = Table(
        [[Paragraph("SENTINEL", styles["CoverTitle"])],
         [Paragraph("Security status report for business owners", styles["CoverSub"])],
         [Paragraph("TrinTech Digital Defense · Trinidad &amp; Tobago / Caribbean", styles["CoverSub"])]],
        colWidths=[170 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), navy),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(banner)
    story.append(Spacer(1, 10))

    # Meta strip
    meta = Table([
        [Paragraph(f"<b>Client</b><br/>{client}", styles["Cell"]),
         Paragraph(f"<b>Host</b><br/>{host}", styles["Cell"]),
         Paragraph(f"<b>Generated</b><br/>{ts}", styles["Cell"])],
        [Paragraph(f"<b>IP</b><br/>{ip}", styles["Cell"]),
         Paragraph(f"<b>Report ID</b><br/>{file_ts}", styles["Cell"]),
         Paragraph("<b>Prepared by</b><br/>TrinTech Digital Defense", styles["Cell"])],
    ], colWidths=[56 * mm, 56 * mm, 56 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta)
    story.append(Spacer(1, 12))

    # Verdict box
    story.append(Paragraph("Overall status", styles["H2"]))
    verdict_tbl = Table([
        [Paragraph(headline, styles["Verdict"])],
        [Paragraph(explanation, styles["VerdictBody"])],
    ], colWidths=[170 * mm])
    verdict_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1.5, accent),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_tbl)

    # Protection checklist
    story.append(Paragraph("Protection at a glance", styles["H2"]))
    story.append(Paragraph(
        "These are the main defenses Sentinel runs on this host. "
        "Green-style “Running / intact” means the control is present; amber or not-running means follow-up.",
        styles["BodyT"],
    ))
    header = [
        Paragraph("<b>Control</b>", styles["CellBold"]),
        Paragraph("<b>Status</b>", styles["CellBold"]),
        Paragraph("<b>What it means</b>", styles["CellBold"]),
    ]
    data = [header]
    for name, st, note in _protection_rows(status):
        data.append([
            Paragraph(name, styles["CellBold"]),
            Paragraph(st, styles["Cell"]),
            Paragraph(note, styles["Cell"]),
        ])
    pt = Table(data, colWidths=[42 * mm, 38 * mm, 90 * mm])
    pt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, light]),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(pt)

    # What Sentinel does
    story.append(Paragraph("What Sentinel does for you", styles["H2"]))
    story.append(Paragraph(
        "Sentinel is continuous monitoring and early warning for small and medium businesses. "
        "It watches for suspicious programs (including reverse-shell style activity), tracks important file changes, "
        "plants canary files that act like digital tripwires, and can help block repeated SSH guessing attacks. "
        "It is designed to give clear visibility without the cost of a full security operations centre.",
        styles["BodyT"],
    ))

    # Recent activity categorized
    story.append(Paragraph("Recent activity (simplified)", styles["H2"]))
    buckets = _categorize_recent(status)
    any_lines = False
    for title, lines in buckets.items():
        if not lines:
            continue
        any_lines = True
        story.append(Paragraph(f"<b>{title}</b>", styles["BodyT"]))
        for line in lines[:12]:
            story.append(Paragraph(f"• {line}", styles["BodyT"]))
    if not any_lines:
        story.append(Paragraph("No notable recent alerts in the current snapshot.", styles["BodyT"]))
    story.append(Paragraph(
        "First-time runs often show many “new” system items while Sentinel learns a normal baseline. "
        "That is expected and usually settles after baselines are saved.",
        styles["Foot"],
    ))

    # Next steps
    story.append(Paragraph("Recommended next steps", styles["H2"]))
    if level == "green":
        steps = [
            "Keep continuous monitoring running (always-on service).",
            "Review this report monthly or after major IT changes.",
            "Do not delete canary files or disable monitoring without telling your security contact.",
            "Ask TrinTech for a technical export if auditors need more detail.",
        ]
    elif level == "amber":
        steps = [
            "Share this report with TrinTech Digital Defense for a guided review.",
            "Confirm the always-on service is installed and heartbeat is fresh.",
            "After authorized IT changes, refresh integrity baselines so noise drops.",
            "Keep canaries and monitoring enabled until the review is complete.",
        ]
    else:
        steps = [
            "Contact TrinTech Digital Defense promptly and share this report.",
            "Do not ignore open critical alerts — acknowledge only after review.",
            "Preserve logs and avoid wiping the host until advised.",
            "If canaries were touched, treat it as a lead to investigate, not automatic proof of breach.",
        ]
    for s in steps:
        story.append(Paragraph(f"• {s}", styles["BodyT"]))

    # Contact
    story.append(Paragraph("About this report", styles["H2"]))
    story.append(Paragraph(
        "Prepared by <b>TrinTech Digital Defense</b> using Sentinel continuous monitoring. "
        "This document is written for owners and managers. It is <b>not</b> a certification that systems are "
        "free of compromise, and it is <b>not</b> legal advice. Technical detail and evidence packs are available on request.",
        styles["BodyT"],
    ))
    story.append(Paragraph(
        "Authorized defensive use only · Caribbean SMB focused · Pilot / supervised deployments recommended for new sites.",
        styles["SmallCenter"],
    ))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=teal, spaceAfter=6))
    story.append(Paragraph(
        f"Report ID {file_ts} · Host {host} · {ts} · TrinTech Digital Defense",
        styles["Foot"],
    ))

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"Sentinel Report — {client}",
        author="TrinTech Digital Defense",
    )
    doc.build(story)
    return {
        "ok": True,
        "path": str(out_path),
        "headline": headline,
        "level": level,
        "client": client,
    }


if __name__ == "__main__":
    print(generate_client_pdf())
