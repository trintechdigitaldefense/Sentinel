# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Technical operator PDF — accurate status for Sentinel dashboard."""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _logo() -> Optional[Path]:
    base = Path(__file__).resolve().parent / "assets"
    for name in ("trintech_logo_header.png", "trintech_sentinel_logo.png", "trintech_brand.png"):
        p = base / name
        if p.is_file() and p.stat().st_size > 100:
            return p
    return None

def _version() -> str:
    try:
        from sentinel import __version__
        return str(__version__)
    except Exception:
        return "3.x"

def _gather() -> dict[str, Any]:
    out: dict[str, Any] = {
        "ts": datetime.now().isoformat(),
        "host": socket.gethostname(),
        "version": _version(),
    }
    try:
        out["ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        out["ip"] = "—"

    # alerts
    alerts = []
    ap = _data() / "alerts.log"
    if ap.exists():
        try:
            for line in ap.read_text(errors="ignore").splitlines()[-50:]:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
        except Exception:
            pass
    out["alerts"] = list(reversed(alerts))
    out["alert_count"] = len(alerts)

    # fleet
    try:
        from modules.network_fleet import fleet_status
        out["fleet"] = fleet_status()
    except Exception as e:
        out["fleet"] = {"ok": False, "error": str(e), "count": 0, "devices": {}}

    # agents
    try:
        from modules.remote_agent import list_remote_agents
        out["agents"] = list_remote_agents()
    except Exception as e:
        out["agents"] = {"ok": False, "error": str(e), "count": 0, "agents": {}}

    # critical
    try:
        from modules.critical_alerts import status as crit_status
        out["critical"] = crit_status()
    except Exception:
        out["critical"] = {"open": [], "open_count": 0}

    # ops / heartbeat
    hb = _data() / "heartbeat.json"
    if hb.exists():
        try:
            out["heartbeat"] = json.loads(hb.read_text())
        except Exception:
            out["heartbeat"] = {}
    else:
        out["heartbeat"] = {}

    # FIM
    fim = _data() / "integrity_baseline" / "integrity_baseline.json"
    out["fim_baseline"] = fim.exists()

    # canaries tracker
    canary = 0
    for p in (
        _data() / "deception_artifacts" / "config.json",
        Path.home() / ".sentinel" / "data" / "deception_artifacts" / "config.json",
    ):
        if p.exists():
            try:
                canary = max(canary, len(json.loads(p.read_text())))
            except Exception:
                pass
    out["canary_files"] = canary

    # service
    try:
        from modules.phase5 import service_status
        out["service"] = service_status()
    except Exception:
        out["service"] = {}

    return out


def generate_technical_pdf(out_path: Optional[Path] = None) -> dict:
    """Write a technical PDF with live operator data."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, Image, Preformatted,
        )
    except ImportError as e:
        return {"ok": False, "error": f"reportlab required: {e}"}

    data = _gather()
    reports = _data() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = reports / f"Sentinel_Technical_{ts}.pdf"
    out_path = Path(out_path)

    navy = HexColor("#0b1f3a")
    teal = HexColor("#0e7c7b")
    gray = HexColor("#4a5568")
    light = HexColor("#f0f4f8")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="T", fontName="Helvetica-Bold", fontSize=16, textColor=navy, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name="H", fontName="Helvetica-Bold", fontSize=11, textColor=teal, spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle(name="B", fontName="Helvetica", fontSize=9, textColor=black, leading=12, spaceAfter=3))
    styles.add(ParagraphStyle(name="S", fontName="Helvetica", fontSize=8, textColor=gray, leading=10))
    styles.add(ParagraphStyle(name="C", fontName="Courier", fontSize=7.5, textColor=navy, leading=9))

    story = []
    logo = _logo()
    if logo:
        try:
            story.append(Image(str(logo), width=0.7 * inch, height=0.7 * inch))
        except Exception:
            pass
    story.append(Paragraph("SENTINEL TECHNICAL REPORT", styles["T"]))
    story.append(Paragraph(
        f"TrinTech Digital Defense · v{data.get('version')} · Operator detail · Authorized defensive use only",
        styles["S"],
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=teal, spaceAfter=8))

    story.append(Paragraph("1. Host snapshot", styles["H"]))
    story.append(Paragraph(
        f"<b>Host:</b> {data.get('host')} &nbsp; <b>IP:</b> {data.get('ip')}<br/>"
        f"<b>Generated:</b> {data.get('ts')}<br/>"
        f"<b>FIM baseline:</b> {'yes' if data.get('fim_baseline') else 'no'} &nbsp; "
        f"<b>Local canary files:</b> {data.get('canary_files', 0)}",
        styles["B"],
    ))

    fleet = data.get("fleet") or {}
    agents = data.get("agents") or {}
    crit = data.get("critical") or {}
    story.append(Paragraph("2. Fleet & agents", styles["H"]))
    story.append(Paragraph(
        f"<b>Fleet hosts:</b> {fleet.get('count', 0)} &nbsp; "
        f"<b>Scan method:</b> {fleet.get('scan_method') or '—'}<br/>"
        f"<b>Canaries planted:</b> {fleet.get('canary_planted', 0)} &nbsp; "
        f"<b>Pending agent canaries:</b> {fleet.get('canary_pending_agent', 0)}<br/>"
        f"<b>Remote agents:</b> {agents.get('count', 0)} &nbsp; "
        f"<b>Open critical:</b> {crit.get('open_count', len(crit.get('open') or []))}",
        styles["B"],
    ))

    # Device table (cap 25)
    devices = list((fleet.get("devices") or {}).items())[:25]
    if devices:
        rows = [[Paragraph("<b>IP</b>", styles["S"]),
                 Paragraph("<b>Status</b>", styles["S"]),
                 Paragraph("<b>Canary</b>", styles["S"]),
                 Paragraph("<b>Source</b>", styles["S"])]]
        for ip, ent in devices:
            if not isinstance(ent, dict):
                ent = {"ip": ip}
            rows.append([
                Paragraph(str(ent.get("ip") or ip), styles["S"]),
                Paragraph(str(ent.get("status") or "—"), styles["S"]),
                Paragraph(str(ent.get("canary") or "—"), styles["S"]),
                Paragraph(str(ent.get("source") or "—"), styles["S"]),
            ])
        tbl = Table(rows, colWidths=[1.6 * inch, 1.3 * inch, 1.6 * inch, 1.5 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 1), (-1, -1), light),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(tbl)

    story.append(Paragraph("3. Recent alerts (up to 20)", styles["H"]))
    alerts = (data.get("alerts") or [])[:20]
    if not alerts:
        story.append(Paragraph("No recent alerts in alerts.log.", styles["B"]))
    else:
        for a in alerts:
            if not isinstance(a, dict):
                continue
            typ = a.get("type") or a.get("event") or a.get("kind") or "ALERT"
            msg = a.get("message") or a.get("detail") or a.get("cmd") or json.dumps(a, default=str)[:160]
            ts = a.get("ts") or a.get("timestamp") or ""
            story.append(Paragraph(f"<b>{typ}</b> <font color='#718096'>{ts}</font><br/>{msg}", styles["B"]))

    story.append(Paragraph("4. Heartbeat / service", styles["H"]))
    hb = data.get("heartbeat") or {}
    svc = data.get("service") or {}
    story.append(Paragraph(
        f"<b>Heartbeat:</b> {json.dumps(hb, default=str)[:300]}<br/>"
        f"<b>Service:</b> {json.dumps(svc, default=str)[:300]}",
        styles["B"],
    ))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=teal, spaceAfter=6))
    story.append(Paragraph(
        "Technical report for operators. Not a certification of clearance. "
        "TrinTech Digital Defense · WhatsApp +1 868 362-0679",
        styles["S"],
    ))

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title="Sentinel Technical Report",
        author="TrinTech Digital Defense",
    )
    doc.build(story)
    return {
        "ok": True,
        "path": str(out_path),
        "type": "technical",
        "version": data.get("version"),
        "alerts": data.get("alert_count"),
        "fleet": fleet.get("count", 0),
    }
