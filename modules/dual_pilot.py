# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Live dual-connector pilot: Sentinel-local + Wazuh (Phase 11 follow-on).

Lab-safe: if Wazuh is unreachable, can inject synthetic second-source alerts
when pilot.lab_mode is true so correlation still exercises the path.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional


def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _save(cfg: dict) -> None:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def ensure_pilot_config(
    window_minutes: int = 45,
    lab_mode: bool = True,
    ai_enabled: bool = False,
    ai_api_key: str = "",
) -> dict:
    """Write sensible pilot defaults without enabling autonomous response."""
    cfg = _cfg()
    connectors = cfg.setdefault("connectors", {})
    connectors.setdefault("sentinel_local", {"enabled": True, "auto_case": True})
    connectors.setdefault(
        "wazuh",
        {
            "enabled": True,
            "url": os.environ.get("WAZUH_URL", ""),
            "user": os.environ.get("WAZUH_USER", ""),
            "password": os.environ.get("WAZUH_PASSWORD", ""),
            "verify_tls": os.environ.get("WAZUH_VERIFY_TLS", "true").lower() not in ("0", "false", "no"),
        },
    )
    cfg["correlation"] = {
        "window_minutes": int(window_minutes),
        "min_sources": 2,
        "min_alerts": 2,
        "promote_min_score": 4,
    }
    cfg["pilot"] = {"lab_mode": bool(lab_mode), "sources": ["sentinel_local", "wazuh"]}
    ai = cfg.setdefault("ai", {})
    ai.setdefault("enabled", bool(ai_enabled))
    if ai_api_key:
        ai["api_key"] = ai_api_key
        ai["enabled"] = True
    ai.setdefault("base_url", "https://api.openai.com/v1")
    ai.setdefault("model", "gpt-4o-mini")
    resp = cfg.setdefault("response", {})
    resp.setdefault("enabled", False)
    resp.setdefault("block_ip", False)
    resp.setdefault("kill_process", False)
    _save(cfg)
    return cfg


def _as_dict(a: Any) -> dict:
    if hasattr(a, "to_dict"):
        return a.to_dict()
    return dict(a) if isinstance(a, dict) else {"raw": a}


def _synthetic_wazuh(host: str = "pilot-host") -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "wazuh-lab-1",
            "source": "wazuh",
            "source_event_id": "lab-auth-1",
            "severity": "high",
            "title": "Wazuh lab: authentication failure burst",
            "occurred_at": (now - timedelta(minutes=5)).isoformat(),
            "received_at": now.isoformat(),
            "asset_id": host,
            "host": host,
            "detail": "Synthetic alert for dual-connector pilot lab_mode",
        },
        {
            "id": "wazuh-lab-2",
            "source": "wazuh",
            "source_event_id": "lab-fim-1",
            "severity": "medium",
            "title": "Wazuh lab: FIM change on /etc/passwd",
            "occurred_at": (now - timedelta(minutes=3)).isoformat(),
            "received_at": now.isoformat(),
            "asset_id": host,
            "host": host,
            "detail": "Synthetic alert for dual-connector pilot lab_mode",
        },
    ]


def _synthetic_local(host: str = "pilot-host") -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "local-lab-1",
            "source": "sentinel_local",
            "source_event_id": "lab-canary-1",
            "severity": "critical",
            "title": "Sentinel lab: canary file touched",
            "occurred_at": (now - timedelta(minutes=4)).isoformat(),
            "received_at": now.isoformat(),
            "asset_id": host,
            "host": host,
            "detail": "Synthetic local alert for dual-connector pilot",
        }
    ]


def run_pilot(
    window_minutes: Optional[int] = None,
    promote: bool = True,
    lab_mode: Optional[bool] = None,
    inject_lab_alerts: bool = True,
) -> dict:
    """Fetch local + Wazuh, correlate, optional promote + AI offline note on first case."""
    from modules.correlation import correlate, promote_bundle_to_case
    from modules.connectors import get_connector

    cfg = _cfg()
    pilot = cfg.get("pilot") or {}
    corr = cfg.get("correlation") or {}
    window = int(window_minutes or corr.get("window_minutes") or 45)
    if lab_mode is None:
        lab_mode = bool(pilot.get("lab_mode", True))

    sources = ["sentinel_local", "wazuh"]
    all_alerts: list[dict] = []
    health: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for name in sources:
        cconf = (cfg.get("connectors") or {}).get(name) or {}
        try:
            conn = get_connector(name, cconf)
            h = conn.health_check()
            health[name] = h.to_dict() if hasattr(h, "to_dict") else dict(h)
            alerts, _ = conn.fetch_events(limit=50)
            for a in alerts:
                d = _as_dict(a)
                d.setdefault("source", name)
                all_alerts.append(d)
        except Exception as e:
            errors[name] = str(e)
            health[name] = {"ok": False, "message": str(e)}

    used_lab = False
    if inject_lab_alerts and lab_mode:
        wazuh_ok = (health.get("wazuh") or {}).get("ok")
        have_wazuh = any(a.get("source") == "wazuh" for a in all_alerts)
        have_local = any(a.get("source") == "sentinel_local" for a in all_alerts)
        if not have_wazuh or not wazuh_ok:
            all_alerts.extend(_synthetic_wazuh())
            used_lab = True
        if not have_local:
            all_alerts.extend(_synthetic_local())
            used_lab = True

    bundles = correlate(
        all_alerts,
        window_minutes=window,
        min_sources=int(corr.get("min_sources") or 2),
        min_alerts=int(corr.get("min_alerts") or 2),
    )
    promoted = []
    ai_notes = []
    if promote:
        min_score = int(corr.get("promote_min_score") or 4)
        for b in bundles:
            if (b.get("score") or 0) >= min_score:
                r = promote_bundle_to_case(b, actor="dual_pilot")
                if r.get("ok"):
                    cid = r["case"]["id"]
                    promoted.append(cid)
                    try:
                        from modules.ai_assist import summarize_case

                        ai_notes.append(summarize_case(cid))
                    except Exception as e:
                        ai_notes.append({"ok": False, "error": str(e), "case_id": cid})

    return {
        "ok": True,
        "window_minutes": window,
        "lab_mode": lab_mode,
        "used_lab_alerts": used_lab,
        "health": health,
        "errors": errors,
        "alert_count": len(all_alerts),
        "bundle_count": len(bundles),
        "bundles": [
            {k: v for k, v in b.items() if k != "alerts"}
            | {"alert_ids": [a.get("id") for a in (b.get("alerts") or [])]}
            for b in bundles
        ],
        "promoted_cases": promoted,
        "ai_notes": ai_notes,
    }
