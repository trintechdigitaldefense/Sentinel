# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Scheduled client PDF reporting (feature 12)."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.report")


def _trend(alerts_path: Path, days: int = 7) -> dict:
    if not alerts_path.exists():
        return {"count": 0, "by_sev": {}}
    cutoff = datetime.now() - timedelta(days=days)
    by = {}
    n = 0
    for line in alerts_path.read_text(errors="ignore").splitlines():
        try:
            rec = json.loads(line)
            ts = datetime.fromisoformat(rec.get("ts", "")[:19])
            if ts < cutoff:
                continue
            n += 1
            sev = rec.get("severity") or "INFO"
            by[sev] = by.get(sev, 0) + 1
        except Exception:
            continue
    return {"count": n, "by_sev": by}


def run_scheduled(schedule: str = "weekly", email_cfg: Optional[dict] = None, data_dir: Optional[Path] = None) -> dict:
    from modules.client_report import generate_client_pdf

    data_dir = data_dir or (Path.home() / ".sentinel" / "data")
    days = 7 if schedule == "weekly" else 30
    trend = _trend(data_dir / "alerts.log", days=days)
    result = generate_client_pdf()
    result["trend"] = trend
    result["schedule"] = schedule

    # Email if configured
    em = email_cfg or {}
    if result.get("ok") and em.get("enabled") and em.get("to_emails"):
        try:
            from modules.alerting import AlertEngine
            engine = AlertEngine({"email": em, "dedup_minutes": 0})
            engine.send(
                "INFO",
                f"Scheduled {schedule} SENTINEL report",
                f"Report: {result.get('path')}\nAlerts last {days}d: {trend}",
            )
            result["emailed"] = True
        except Exception as e:
            result["emailed"] = False
            result["email_error"] = str(e)
    return result
