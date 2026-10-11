#!/usr/bin/env python3
"""FEATURE 17 — Fleet risk console."""
from __future__ import annotations
import json
import os
from datetime import datetime
from pathlib import Path

def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _score_client(row: dict) -> float:
    score = 0.0
    drift = row.get("drift_score")
    if drift is not None:
        score += max(0, 100 - float(drift)) * 0.4
    score += min(50, int(row.get("open_alerts") or 0) * 2)
    if row.get("heartbeat_ok") is False:
        score += 40
    age = row.get("oldest_alert_age_hours")
    if age:
        score += min(30, float(age) * 0.5)
    if row.get("posture_grade") == "F":
        score += 20
    elif row.get("posture_grade") == "D":
        score += 10
    return round(score, 1)

def collect_local() -> dict:
    row = {"client": "local", "host": os.uname().nodename if hasattr(os, "uname") else "local",
           "drift_score": None, "open_alerts": 0, "heartbeat_ok": None,
           "oldest_alert_age_hours": 0, "posture_grade": "N/A", "ts": datetime.now().isoformat()}
    try:
        from modules.drift import trend
        row["drift_score"] = trend().get("latest_score")
    except Exception:
        pass
    ap = _data() / "alerts.log"
    if ap.exists():
        try:
            row["open_alerts"] = len([l for l in ap.read_text(errors="ignore").splitlines() if l.strip()][-100:])
        except Exception:
            pass
    try:
        from modules.deadman import check_local
        row["heartbeat_ok"] = bool(check_local().get("alive"))
    except Exception:
        pass
    agents = []
    ad = _data() / "agents"
    if ad.exists():
        for p in ad.glob("*.json"):
            try:
                d = json.loads(p.read_text())
                agents.append({"client": d.get("host") or p.stem, "host": d.get("host") or p.stem,
                               "drift_score": d.get("drift_score"), "open_alerts": d.get("open_alerts") or 0,
                               "heartbeat_ok": d.get("status") == "ok",
                               "oldest_alert_age_hours": d.get("oldest_alert_age_hours") or 0,
                               "posture_grade": d.get("posture_grade") or "N/A",
                               "ts": d.get("received_at") or ""})
            except Exception:
                pass
    rows = [row] + agents
    for r in rows:
        r["risk_score"] = _score_client(r)
    rows.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"ok": True, "generated": datetime.now().isoformat(), "clients": rows}

def print_console() -> dict:
    data = collect_local()
    print()
    print("=" * 64)
    print("  SENTINEL FLEET RISK CONSOLE")
    print("=" * 64)
    print(f"  {'CLIENT':20} {'RISK':>6} {'DRIFT':>7} {'ALERTS':>6} {'HB':>4}")
    print("-" * 64)
    for r in data["clients"]:
        hb = "OK" if r.get("heartbeat_ok") else "!!"
        drift = r.get("drift_score")
        drift_s = f"{drift}%" if drift is not None else "—"
        print(f"  {str(r.get('client'))[:20]:20} {r.get('risk_score'):>6} {drift_s:>7} {r.get('open_alerts'):>6} {hb:>4}")
    print("=" * 64)
    if data["clients"]:
        top = data["clients"][0]
        print(f"  Priority: {top.get('client')} (risk {top.get('risk_score')})")
    print()
    return data

def write_html() -> Path:
    data = collect_local()
    rows = "".join(
        f"<tr><td>{r.get('client')}</td><td>{r.get('risk_score')}</td><td>{r.get('drift_score')}</td>"
        f"<td>{r.get('open_alerts')}</td><td>{'OK' if r.get('heartbeat_ok') else 'DOWN'}</td></tr>"
        for r in data["clients"]
    )
    html = f"""<!DOCTYPE html><html><head><meta charset=utf-8><title>SENTINEL Fleet Console</title>
<style>body{{font-family:system-ui;background:#0B1F3A;color:#E8F0FE;padding:24px}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #1E3A5F;padding:8px;text-align:left}}
h1{{color:#1A8CFF}}</style></head><body>
<h1>Fleet Risk Console</h1><p>Generated {data.get('generated')}</p>
<table><tr><th>Client</th><th>Risk</th><th>Drift</th><th>Alerts</th><th>Heartbeat</th></tr>
{rows}</table></body></html>"""
    out = _data() / "fleet_console.html"
    out.write_text(html)
    return out
