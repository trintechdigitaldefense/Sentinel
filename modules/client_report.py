# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Professional plain-language PDF security report for non-technical clients."""
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


def _logo_path(*, header: bool = False) -> Optional[Path]:
    """Official TrinTech brand circle only (marketing artwork)."""
    here = Path(__file__).resolve().parent / "assets"
    # header uses slightly smaller file for lean PDFs; same artwork
    ordered = [
        here / "trintech_logo_header.png",
        here / "trintech_sentinel_logo.png",
        here / "trintech_brand.png",
    ]
    for cand in ordered:
        if cand.is_file() and cand.stat().st_size > 100:
            return cand
    return None


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
            f"{open_crit} critical alert(s) still need operator acknowledgement. "
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
            "Investigation is recommended.",
            "red",
        )
    if open_alerts > 25:
        return (
            "Elevated alert volume",
            f"About {open_alerts} recent security events were recorded. "
            "A guided review of the highest-priority items is recommended.",
            "amber",
        )
    if open_alerts > 10:
        return (
            "Elevated alert volume",
            f"About {open_alerts} recent security events were recorded. "
            "Most may be routine; a review of priority items is recommended.",
            "amber",
        )
    if drift is not None:
        try:
            if float(drift) < 90:
                return (
                    "System changes detected",
                    f"File integrity is at about {float(drift):.0f}% of the known-good baseline. "
                    "Confirm whether these changes were authorized.",
                    "amber",
                )
        except Exception:
            pass
    if ready in ("PARTIAL", "WARN"):
        return (
            "Protection partially ready",
            "Most defenses are in place, but go-live still reports partial status. "
            "Finish remaining setup with TrinTech.",
            "amber",
        )
    return (
        "All clear",
        "Continuous monitoring is active, digital tripwires are intact, and there are no critical open issues. "
        "Your systems are under normal Sentinel protection.",
        "green",
    )


def _protection_rows(status: dict) -> list[tuple[str, str, str]]:
    rows = []
    alive = _heartbeat_ok(status)
    rows.append((
        "Continuous monitoring",
        "Running" if alive else "Not running",
        "Live heartbeat from hunt/service" if alive else "Start service-install or hunt",
    ))
    can_ok, can_total = _canary_counts(status)
    if can_total:
        rows.append(("Canary tripwires", f"{can_ok}/{can_total} intact", "Decoy files that alert if opened"))
    else:
        rows.append(("Canary tripwires", "Not deployed", "Run deception / go-live"))

    gl = status.get("go_live") or {}
    steps = (gl.get("steps") if isinstance(gl, dict) else None) or {}
    fim_ok = isinstance(steps, dict) and steps.get("fim_baseline") in ("ok", "OK", True)
    fim = status.get("fim") or status.get("integrity") or {}
    if fim_ok or (isinstance(fim, dict) and (fim.get("baseline") or fim.get("files"))):
        n = (fim.get("files") if isinstance(fim, dict) else None) or "active"
        rows.append(("File integrity (FIM)", "Baseline active", f"Tracking {n} paths" if n != "active" else "Known-good snapshot"))
    else:
        rows.append(("File integrity (FIM)", "Check recommended", "Run integrity / go-live"))

    svc = status.get("service") or {}
    active = isinstance(svc, dict) and (svc.get("active") or svc.get("running"))
    rows.append(("Always-on service", "Installed" if active else "Not installed", "Survives logout when installed"))

    fw = status.get("firewall") or {}
    backend = (fw.get("backend") if isinstance(fw, dict) else None) or "host"
    rows.append(("Host firewall", str(backend), "Host control — not a perimeter appliance"))

    crit = status.get("critical") or {}
    open_crit = len(crit.get("open") or []) if isinstance(crit, dict) else 0
    rows.append(("Critical alerts", "None open" if open_crit == 0 else f"{open_crit} open", "Stay open until acknowledged"))
    rows.append(("Recent alerts", str(_alert_count(status)), "May include first-run baseline noise"))
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
    buckets = {"Needs attention": [], "Baseline / routine": [], "Other": []}
    recent = status.get("recent_alerts") or status.get("alerts") or []
    if not isinstance(recent, list):
        return buckets
    attention_keys = (
        "REVERSE_SHELL", "CANARY", "LD_PRELOAD", "CRITICAL", "SELF_INTEGRITY",
        "TAMPER", "BRUTE", "SSH_BLOCK", "RANSOM", "WEB_SHELL",
    )
    routine_keys = (
        "NEW_SUID", "NEW_PERSISTENCE", "NEW_CRON", "RC_FILE", "FIM_MODIFIED",
        "REMOVED_PERSISTENCE", "SYSTEMD",
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
    """Generate a professional non-technical PDF report with logo."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, Image, Flowable,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
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
    ts = datetime.now().strftime("%d %B %Y · %H:%M")
    file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(out_path) if out_path else (_data() / "reports" / f"Client_Report_{file_ts}.pdf")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    headline, explanation, level = _plain_verdict(status)
    level_map = {
        "green": (colors.HexColor("#059669"), colors.HexColor("#ECFDF5"), "STABLE"),
        "amber": (colors.HexColor("#D97706"), colors.HexColor("#FFFBEB"), "REVIEW"),
        "red": (colors.HexColor("#DC2626"), colors.HexColor("#FEF2F2"), "ACTION"),
    }
    accent, soft_bg, badge = level_map.get(level, level_map["amber"])
    navy = colors.HexColor("#0B1F3A")
    teal = colors.HexColor("#0E7C7B")
    slate = colors.HexColor("#334155")
    muted = colors.HexColor("#64748B")
    light = colors.HexColor("#F1F5F9")
    white = colors.white

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Brand", fontName="Helvetica-Bold", fontSize=16,
                              textColor=white, leading=20, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="BrandSub", fontName="Helvetica", fontSize=8.5,
                              textColor=colors.HexColor("#94A3B8"), leading=11, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="DocTitle", fontName="Helvetica-Bold", fontSize=11,
                              textColor=white, leading=14, alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="DocMeta", fontName="Helvetica", fontSize=8,
                              textColor=colors.HexColor("#94A3B8"), leading=10, alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=11,
                              textColor=navy, spaceBefore=14, spaceAfter=6, leading=14))
    styles.add(ParagraphStyle(name="BodyT", fontName="Helvetica", fontSize=9,
                              textColor=slate, leading=12.5, spaceAfter=3, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="VerdictH", fontName="Helvetica-Bold", fontSize=15,
                              textColor=accent, alignment=TA_CENTER, spaceBefore=4, spaceAfter=4, leading=18))
    styles.add(ParagraphStyle(name="VerdictB", fontName="Helvetica", fontSize=9.5,
                              textColor=slate, alignment=TA_CENTER, leading=13, spaceAfter=4))
    styles.add(ParagraphStyle(name="Badge", fontName="Helvetica-Bold", fontSize=8,
                              textColor=white, alignment=TA_CENTER, leading=10))
    styles.add(ParagraphStyle(name="Foot", fontName="Helvetica", fontSize=7.5,
                              textColor=muted, leading=10, spaceAfter=1))
    styles.add(ParagraphStyle(name="Cell", fontName="Helvetica", fontSize=8, leading=11, textColor=slate))
    styles.add(ParagraphStyle(name="CellBold", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=navy))
    styles.add(ParagraphStyle(name="TH", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=white))
    styles.add(ParagraphStyle(name="CenterMuted", fontName="Helvetica", fontSize=8,
                              textColor=muted, alignment=TA_CENTER, leading=10))

    story: list = []
    logo = _logo_path(header=True)
    logo_full = _logo_path(header=True)

    # ── Header with logo ──────────────────────────────────────────
    left_cell = []
    if logo:
        try:
            left_cell.append(Image(str(logo), width=20 * mm, height=20 * mm, mask="auto"))
        except Exception:
            try:
                left_cell.append(Image(str(logo), width=20 * mm, height=20 * mm))
            except Exception:
                pass
    left_text = Table([
        [Paragraph("TRINTECH DIGITAL DEFENSE", styles["Brand"])],
        [Paragraph("Caribbean cybersecurity · Authorized defensive use only", styles["BrandSub"])],
    ], colWidths=[95 * mm])
    left_text.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    if left_cell:
        brand_inner = Table([[left_cell[0], left_text]], colWidths=[18 * mm, 95 * mm])
        brand_inner.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        left_flow = brand_inner
    else:
        left_flow = left_text

    right_flow = Table([
        [Paragraph("SENTINEL STATUS REPORT", styles["DocTitle"])],
        [Paragraph(ts, styles["DocMeta"])],
        [Paragraph(f"ID {file_ts}", styles["DocMeta"])],
    ], colWidths=[55 * mm])
    right_flow.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
    ]))

    header = Table([[left_flow, right_flow]], colWidths=[118 * mm, 55 * mm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), navy),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(header)
    # teal accent line
    story.append(Table([[""]], colWidths=[173 * mm], rowHeights=[2.5]))
    story[-1].setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), teal)]))
    story.append(Spacer(1, 10))

    # ── Client meta ───────────────────────────────────────────────
    meta = Table([
        [
            Paragraph(f"<b>Prepared for</b><br/>{client}", styles["Cell"]),
            Paragraph(f"<b>Host</b><br/>{host}", styles["Cell"]),
            Paragraph(f"<b>Network address</b><br/>{ip}", styles["Cell"]),
            Paragraph(f"<b>Classification</b><br/>Confidential — client", styles["Cell"]),
        ],
    ], colWidths=[43 * mm, 43 * mm, 43 * mm, 44 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(meta)
    story.append(Spacer(1, 8))
    # Brand emblem (official TrinTech artwork)
    if logo_full:
        try:
            emblem = Image(str(logo_full), width=48 * mm, height=48 * mm, mask="auto")
        except Exception:
            try:
                emblem = Image(str(logo_full), width=48 * mm, height=48 * mm)
            except Exception:
                emblem = None
        if emblem is not None:
            emb_tbl = Table([[emblem]], colWidths=[173 * mm])
            emb_tbl.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(emb_tbl)
            story.append(Paragraph(
                "Defend · Detect · Dominate — Your Caribbean Cybersecurity Guardians",
                styles["CenterMuted"],
            ))
            story.append(Spacer(1, 8))
    else:
        story.append(Spacer(1, 4))

    # ── Executive verdict ─────────────────────────────────────────
    story.append(Paragraph("1. Executive status", styles["H2"]))
    badge_tbl = Table([[Paragraph(badge, styles["Badge"])]], colWidths=[28 * mm])
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), accent),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    verdict_inner = Table([
        [badge_tbl],
        [Paragraph(headline, styles["VerdictH"])],
        [Paragraph(explanation, styles["VerdictB"])],
    ], colWidths=[165 * mm])
    verdict_inner.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, -1), soft_bg),
        ("BOX", (0, 0), (-1, -1), 1.2, accent),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(verdict_inner)

    # ── Protection table ──────────────────────────────────────────
    story.append(Paragraph("2. Protection at a glance", styles["H2"]))
    story.append(Paragraph(
        "Summary of defenses currently observed on this host. "
        "“Running / intact” indicates the control is present; follow-up items are noted in plain language.",
        styles["BodyT"],
    ))
    data = [[
        Paragraph("Control", styles["TH"]),
        Paragraph("Status", styles["TH"]),
        Paragraph("Notes", styles["TH"]),
    ]]
    for name, st, note in _protection_rows(status):
        data.append([
            Paragraph(name, styles["CellBold"]),
            Paragraph(st, styles["Cell"]),
            Paragraph(note, styles["Cell"]),
        ])
    pt = Table(data, colWidths=[45 * mm, 38 * mm, 90 * mm])
    pt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("BACKGROUND", (0, 1), (-1, -1), white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, light]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(pt)

    # ── Capability narrative ──────────────────────────────────────
    story.append(Paragraph("3. What Sentinel provides", styles["H2"]))
    story.append(Paragraph(
        "Sentinel is continuous monitoring and early warning for small and medium businesses across the Caribbean. "
        "It watches for suspicious programs (including reverse-shell style activity), tracks important file changes, "
        "plants canary files that act as digital tripwires, and can help contain repeated SSH guessing attacks. "
        "The goal is clear visibility and faster response — without the cost or complexity of a full security operations centre.",
        styles["BodyT"],
    ))

    # ── Activity ──────────────────────────────────────────────────
    story.append(Paragraph("4. Recent activity (simplified)", styles["H2"]))
    buckets = _categorize_recent(status)
    any_lines = False
    for title, lines in buckets.items():
        if not lines:
            continue
        any_lines = True
        story.append(Paragraph(f"<b>{title}</b>", styles["BodyT"]))
        for line in lines[:10]:
            story.append(Paragraph(f"• {line}", styles["BodyT"]))
    if not any_lines:
        story.append(Paragraph("No notable recent alerts in the current snapshot.", styles["BodyT"]))
    story.append(Paragraph(
        "Note: First-time deployments often show many “new” system items while Sentinel learns a normal baseline. "
        "That usually settles after baselines are saved.",
        styles["Foot"],
    ))

    # ── Recommendations ───────────────────────────────────────────
    story.append(Paragraph("5. Recommended next steps", styles["H2"]))
    if level == "green":
        steps = [
            "Keep continuous monitoring running (always-on service).",
            "Review this report monthly or after major IT changes.",
            "Do not delete canary files or disable monitoring without informing your security contact.",
            "Request a technical export from TrinTech if auditors need deeper detail.",
        ]
    elif level == "amber":
        steps = [
            "Share this report with TrinTech Digital Defense for a guided review.",
            "Confirm the always-on service is installed and the heartbeat is fresh.",
            "After authorized IT changes, refresh integrity baselines to reduce noise.",
            "Keep canaries and monitoring enabled until the review is complete.",
        ]
    else:
        steps = [
            "Contact TrinTech Digital Defense promptly and share this report.",
            "Do not ignore open critical alerts — acknowledge only after review.",
            "Preserve logs; avoid wiping the host until advised.",
            "Treat disturbed canaries as investigation leads, not automatic proof of breach.",
        ]
    for i, s in enumerate(steps, 1):
        story.append(Paragraph(f"<b>{i}.</b>  {s}", styles["BodyT"]))

    # ── Closing ───────────────────────────────────────────────────
    story.append(Paragraph("6. Scope and limitations", styles["H2"]))
    story.append(Paragraph(
        "This report is prepared by <b>TrinTech Digital Defense</b> using the Sentinel continuous-monitoring platform. "
        "It is written for owners and managers. It is <b>not</b> a certification that systems are free of compromise, "
        "and it is <b>not</b> legal advice. Findings are based on host visibility at generation time. "
        "Technical evidence packs and operator detail are available on request.",
        styles["BodyT"],
    ))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1.2, color=teal, spaceBefore=2, spaceAfter=8))

    foot_left = Paragraph(
        "TrinTech Digital Defense<br/>Trinidad &amp; Tobago · Caribbean SMB security<br/>WhatsApp: +1 868 362-0679",
        styles["Foot"],
    )
    foot_right = Paragraph(
        f"Report ID {file_ts}<br/>Host {host} · Confidential",
        styles["Foot"],
    )
    foot = Table([[foot_left, foot_right]], colWidths=[95 * mm, 78 * mm])
    foot.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(foot)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Authorized defensive use only · Pilot / supervised deployments recommended for new sites",
        styles["CenterMuted"],
    ))

    def _page(canvas_obj, doc):
        canvas_obj.saveState()
        canvas_obj.setStrokeColor(colors.HexColor("#E2E8F0"))
        canvas_obj.setLineWidth(0.4)
        canvas_obj.line(18 * mm, 12 * mm, A4[0] - 18 * mm, 12 * mm)
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(muted)
        canvas_obj.drawString(18 * mm, 7 * mm, "TrinTech Digital Defense — Sentinel")
        canvas_obj.drawRightString(A4[0] - 18 * mm, 7 * mm, f"Page {doc.page}")
        canvas_obj.restoreState()

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=12 * mm,
        bottomMargin=18 * mm,
        title=f"Sentinel Status Report — {client}",
        author="TrinTech Digital Defense",
        subject="Client security status report",
        creator="Sentinel by TrinTech Digital Defense",
    )
    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return {
        "ok": True,
        "path": str(out_path),
        "headline": headline,
        "level": level,
        "client": client,
        "logo": str(logo) if logo else None,
    }


if __name__ == "__main__":
    print(generate_client_pdf())
