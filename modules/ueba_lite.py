# © 2026 TrinTech Digital Defense — authorized defensive use only
"""UEBA-lite host scoring (Phase 12 foundation).

NOT enterprise UEBA. Scores hosts from local alert/case velocity vs a
simple rolling baseline. Useful for MSP triage prioritization only.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        s = str(value)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s[:26])
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _load_alerts(days: int = 14) -> list[dict]:
    path = _home() / "data" / "alerts.log"
    if not path.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        ts = _parse_ts(rec.get("ts") or rec.get("occurred_at"))
        if ts and ts < cutoff:
            continue
        out.append(rec)
    return out


def score_hosts(window_hours: int = 24, baseline_days: int = 7) -> dict:
    """Return per-host scores: recent rate vs baseline rate."""
    alerts = _load_alerts(days=max(baseline_days, 2))
    now = datetime.now(timezone.utc)
    recent_cut = now - timedelta(hours=window_hours)
    base_cut = now - timedelta(days=baseline_days)

    recent = defaultdict(int)
    baseline = defaultdict(int)
    for a in alerts:
        host = str(a.get("host") or a.get("asset_id") or a.get("hostname") or "unknown").lower()
        ts = _parse_ts(a.get("ts") or a.get("occurred_at")) or now
        if ts >= recent_cut:
            recent[host] += 1
        if base_cut <= ts < recent_cut:
            baseline[host] += 1

    try:
        from modules import cases

        for st in ("new", "triaging", "investigating", "contained"):
            for c in cases.list_cases(status=st, limit=100):
                host = "case-open"
                title = (c.get("title") or "").lower()
                for token in title.replace("/", " ").split():
                    if token.startswith("pc-") or token.startswith("host"):
                        host = token
                        break
                recent[host] += 2 if c.get("severity") in ("high", "critical") else 1
    except Exception:
        pass

    base_hours = max(1.0, baseline_days * 24 - window_hours)
    scores = []
    hosts = set(recent) | set(baseline)
    for h in hosts:
        r = recent[h]
        b = baseline[h]
        base_rate = b / base_hours
        recent_rate = r / max(1.0, float(window_hours))
        if base_rate <= 0:
            score = min(100.0, r * 15.0)
            band = "elevated" if r else "quiet"
        else:
            ratio = recent_rate / base_rate
            score = min(100.0, ratio * 25.0)
            band = (
                "critical"
                if score >= 80
                else "high"
                if score >= 50
                else "elevated"
                if score >= 25
                else "normal"
            )
        scores.append(
            {
                "host": h,
                "recent_count": r,
                "baseline_count": b,
                "score": round(score, 1),
                "band": band,
            }
        )
    scores.sort(key=lambda x: x["score"], reverse=True)
    return {
        "ok": True,
        "window_hours": window_hours,
        "baseline_days": baseline_days,
        "hosts": scores,
        "note": "UEBA-lite only — not enterprise UEBA",
    }
