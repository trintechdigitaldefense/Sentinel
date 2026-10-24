# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multi-source correlation (Phase 11) — time/host window, not a full SIEM.

Correlate normalized alerts from multiple connectors when they share
host (or agent) and fall inside a time window. Output is candidate
correlation bundles operators can promote to a case.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional


def _parse_ts(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s[:26])
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _host_key(alert: dict) -> str:
    for k in ("host", "hostname", "agent_name", "agent_id", "source_host", "asset_id"):
        v = alert.get(k)
        if v:
            return str(v).strip().lower()
    extra = alert.get("extra") or {}
    if isinstance(extra, dict):
        for k in ("host", "hostname", "agent_name", "agent_id"):
            v = extra.get(k)
            if v:
                return str(v).strip().lower()
    return "unknown"


def _as_dict(a: Any) -> dict:
    if hasattr(a, "to_dict"):
        return a.to_dict()
    return dict(a) if isinstance(a, dict) else {"raw": a}


def correlate(
    alerts: list,
    window_minutes: int = 30,
    min_sources: int = 2,
    min_alerts: int = 2,
) -> list[dict]:
    """Group alerts by host; emit bundles with ≥ min_sources or ≥ min_alerts in window."""
    rows = [_as_dict(a) for a in (alerts or [])]
    by_host: dict[str, list[dict]] = {}
    for a in rows:
        by_host.setdefault(_host_key(a), []).append(a)

    bundles: list[dict] = []
    window = timedelta(minutes=max(1, int(window_minutes)))

    for host, items in by_host.items():
        timed = []
        for a in items:
            ts = _parse_ts(
                a.get("observed_at")
                or a.get("occurred_at")
                or a.get("received_at")
                or a.get("ts")
                or a.get("timestamp")
                or a.get("created_at")
            )
            timed.append((ts or datetime.now(timezone.utc), a))
        timed.sort(key=lambda x: x[0])

        i = 0
        while i < len(timed):
            start_ts, _ = timed[i]
            group = [timed[i]]
            j = i + 1
            while j < len(timed) and timed[j][0] - start_ts <= window:
                group.append(timed[j])
                j += 1
            alerts_g = [g[1] for g in group]
            sources = sorted({str(a.get("source") or a.get("connector") or "unknown") for a in alerts_g})
            sevs = [str(a.get("severity") or "").upper() for a in alerts_g]
            score = len(alerts_g) + 2 * max(0, len(sources) - 1)
            if len(sources) >= min_sources or len(alerts_g) >= min_alerts:
                if len(alerts_g) >= min_alerts or len(sources) >= min_sources:
                    bundles.append(
                        {
                            "id": f"CORR-{host[:24]}-{int(start_ts.timestamp())}",
                            "host": host,
                            "window_start": start_ts.isoformat(),
                            "window_minutes": window_minutes,
                            "sources": sources,
                            "alert_count": len(alerts_g),
                            "severities": sevs,
                            "score": score,
                            "titles": [(a.get("title") or a.get("rule") or "")[:80] for a in alerts_g[:8]],
                            "alerts": alerts_g,
                        }
                    )
            i = i + 1 if j == i + 1 else j

    bundles.sort(key=lambda b: b.get("score", 0), reverse=True)
    return bundles


def correlate_from_connectors(
    sources: Optional[list[str]] = None,
    limit_per: int = 50,
    window_minutes: int = 30,
) -> dict:
    """Fetch from configured connectors and correlate."""
    from modules.connector_enable import load_config
    from modules.connectors import get_connector

    cfg = load_config().get("connectors") or {}
    sources = sources or [k for k, v in cfg.items() if (v or {}).get("enabled", True)]
    if not sources:
        sources = ["sentinel_local"]
    all_alerts = []
    errors = {}
    for name in sources:
        try:
            conn = get_connector(name, cfg.get(name) or {})
            alerts, _ = conn.fetch_events(limit=limit_per)
            for a in alerts:
                d = _as_dict(a)
                d.setdefault("source", name)
                all_alerts.append(d)
        except Exception as e:
            errors[name] = str(e)
    bundles = correlate(all_alerts, window_minutes=window_minutes)
    return {
        "ok": True,
        "sources": sources,
        "alert_count": len(all_alerts),
        "bundle_count": len(bundles),
        "bundles": bundles,
        "errors": errors,
    }


def promote_bundle_to_case(bundle: dict, actor: str = "correlation") -> dict:
    from modules import cases

    titles = bundle.get("titles") or []
    title = f"Correlated: {bundle.get('host')} ({', '.join(bundle.get('sources') or [])})"
    if titles:
        title = f"{title} — {titles[0]}"
    sev = "high"
    for s in bundle.get("severities") or []:
        if s in ("CRITICAL", "critical"):
            sev = "critical"
            break
        if s in ("HIGH", "high"):
            sev = "high"
    summary = (
        f"Auto-correlated {bundle.get('alert_count')} alerts from "
        f"{bundle.get('sources')} on host {bundle.get('host')} "
        f"within {bundle.get('window_minutes')}m. Score={bundle.get('score')}."
    )
    return cases.create_case(
        title=title[:300],
        severity=sev,
        source="correlation",
        summary=summary,
        actor=actor,
        alert_refs=[bundle.get("id")] + [str(a.get("id") or "") for a in (bundle.get("alerts") or [])[:10]],
    )
