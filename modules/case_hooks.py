# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Auto-open cases from high/critical alerts (Phase 7 integration).

Called from send_alert and from connector ingest. Dedupes by source_event_id
so the same alert does not open unlimited cases.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

# Alert types that always open a case (engine critical set + high-signal deception)
AUTO_CASE_TYPES = {
    "REVERSE_SHELL",
    "CANARY_TRIGGERED",
    "CANARY_BEACON",
    "AGENT_REVERSE_SHELL",
    "CANARY_DELETED",
    "CANARY_REAPPEARED",
    "RANSOMWARE",
    "PERSISTENCE",
    "LATERAL_MOVEMENT",
}

HIGH_SEVS = {"high", "critical", "HIGH", "CRITICAL"}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _dedup_path() -> Path:
    return _home() / "data" / "case_auto_dedup.json"


def _load_dedup() -> dict:
    p = _dedup_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_dedup(d: dict) -> None:
    p = _dedup_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d))


def _should_skip(key: str) -> bool:
    d = _load_dedup()
    return key in d


def _mark(key: str, case_id: str) -> None:
    d = _load_dedup()
    d[key] = case_id
    # keep last 500
    if len(d) > 500:
        for k in list(d.keys())[:-500]:
            d.pop(k, None)
    _save_dedup(d)


def maybe_open_case_from_engine_alert(alert_type: str, details: Any, actor: str = "sentinel") -> Optional[dict]:
    """Open a case for critical engine alerts. Returns case result or None."""
    at = (alert_type or "").upper()
    if at not in AUTO_CASE_TYPES:
        return None
    try:
        from modules import cases
    except Exception:
        return None

    detail_s = ""
    if isinstance(details, dict):
        detail_s = json.dumps(details)[:800]
        ref = str(details.get("canary_id") or details.get("path") or details.get("pid") or at)
    else:
        detail_s = str(details)[:800]
        ref = at
    key = f"engine:{at}:{ref}"
    if _should_skip(key):
        return None

    title = f"{at.replace('_', ' ').title()}"
    if isinstance(details, dict) and details.get("path"):
        title = f"{title}: {details['path']}"

    r = cases.create_case(
        title=title[:300],
        severity="critical" if at in {"REVERSE_SHELL", "AGENT_REVERSE_SHELL", "BEHAVIORAL_REVERSE_SHELL", "NEW_SUID", "LD_PRELOAD_CREATED", "RANSOMWARE"} else "high",
        source="sentinel_engine",
        source_event_id=key[:120],
        summary=detail_s,
        actor=actor,
        alert_refs=[key[:200]],
    )
    if r.get("ok") and r.get("case"):
        _mark(key, r["case"]["id"])
    return r


def maybe_open_case_from_normalized(alert: dict, actor: str = "connector") -> Optional[dict]:
    """Open a case from a NormalizedAlert-like dict when severity is high/critical."""
    sev = str(alert.get("severity") or "").lower()
    if sev not in {"high", "critical"}:
        return None
    try:
        from modules import cases
    except Exception:
        return None

    sid = str(alert.get("source_event_id") or alert.get("id") or "")
    key = f"norm:{alert.get('source')}:{sid or alert.get('title')}"
    if _should_skip(key):
        return None

    r = cases.create_from_normalized_alert(alert, actor=actor)
    if r.get("ok") and r.get("case"):
        _mark(key, r["case"]["id"])
    return r
