#!/usr/bin/env python3
"""FEATURE 01 polish — PDF drift report with matplotlib trend chart."""
from __future__ import annotations
import io
import os
from datetime import datetime
from pathlib import Path

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def generate_drift_pdf(out_path: Path = None) -> dict:
    from modules.drift import trend
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return {"ok": False, "error": "matplotlib not installed — pip install matplotlib"}
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        return {"ok": False, "error": "reportlab not installed — pip install reportlab"}

    t = trend()
    hist = t.get("history") or []
    out_path = out_path or (Path.home() / f"Sentinel_Drift_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

    chart_buf = io.BytesIO()
    fig, ax = plt.subplots(figsize=(7.2, 2.8), dpi=120)
    if len(hist) >= 1:
        xs = list(range(len(hist)))
        ys = [float(p.get("score") or 0) for p in hist]
        ax.plot(xs, ys, color="#1A8CFF", linewidth=2, marker="o", markersize=3)
        ax.fill_between(xs, ys, alpha=0.15, color="#1A8CFF")
        ax.set_ylim(0, 105)
        ax.set_ylabel("% baseline intact")
        ax.set_xlabel("Integrity checks (recent)")
        ax.set_title("90-day baseline drift trend")
        ax.grid(True, alpha=0.3)
    else:
        ax.text(0.5, 0.5, "No drift history yet", ha="center", va="center")
        ax.set_axis_off()
    fig.tight_layout()
    fig.savefig(chart_buf, format="png")
    plt.close(fig)
    chart_buf.seek(0)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="T", fontName="Helvetica-Bold", fontSize=16, textColor=HexColor("#0B1F3A"), alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name="B", fontName="Helvetica", fontSize=10, leading=13, spaceAfter=4))
    styles.add(ParagraphStyle(name="V", fontName="Helvetica-Oblique", fontSize=10, textColor=HexColor("#0D7377"), leading=13, spaceAfter=8))

    story = []
    story.append(Paragraph("SENTINEL Drift Report", styles["T"]))
    story.append(Paragraph(f"TrinTech Digital Defense · Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["B"]))
    story.append(HRFlowable(width="100%", thickness=2, color=HexColor("#1A8CFF"), spaceAfter=10))
    story.append(Paragraph(t.get("verdict") or "No verdict", styles["V"]))
    story.append(Paragraph(
        f"Points: {t.get('points')} · Latest: {t.get('latest_score')}% · Oldest: {t.get('oldest_score')}% · Delta: {t.get('delta')}",
        styles["B"],
    ))
    img = Image(chart_buf, width=6.5 * inch, height=2.5 * inch)
    story.append(Spacer(1, 8))
    story.append(img)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This score measures how intact the file-integrity baseline remains over time. "
        "Sustained drops indicate unauthorized change, failed hardening, or legitimate drift that should be re-baselined.",
        styles["B"],
    ))
    doc = SimpleDocTemplate(str(out_path), pagesize=letter,
                            leftMargin=0.7*inch, rightMargin=0.7*inch,
                            topMargin=0.6*inch, bottomMargin=0.6*inch,
                            title="SENTINEL Drift Report", author="TrinTech Digital Defense")
    doc.build(story)
    return {"ok": True, "path": str(out_path), "points": t.get("points"), "verdict": t.get("verdict")}
