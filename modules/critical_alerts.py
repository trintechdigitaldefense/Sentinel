import logging
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Persistent critical alerts — survive restarts until acknowledged.

Critical events are stored in ~/.sentinel/data/critical_alerts.json and
re-surfaced on hunt cycles and ops status until an operator ACKs them.
Quiet hours / hygiene must not drop these (callers should bypass suppress).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Types that always persist (in addition to engine CRITICAL_ALERTS)
DEFAULT_CRITICAL = {
    "REVERSE_SHELL",
    "BEHAVIORAL_REVERSE_SHELL",
    "CANARY_TRIGGERED",
    "CANARY_BEACON",
    "AGENT_REVERSE_SHELL",
    "NEW_SUID",
    "LD_PRELOAD_CREATED",
    "AUTHORIZED_KEYS_DRIFT",
    "SELF_INTEGRITY_VIOLATION",
    "IP_BLOCKED",  # optional high — kept for visibility of active blocks
    "RANSOMWARE",
    "FIM_DELETED",
}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def store_path() -> Path:
    return _data() / "critical_alerts.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    p = store_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    return {"open": {}, "acked": {}, "updated": None}


def _save(data: dict) -> None:
    data["updated"] = _now()
    store_path().write_text(json.dumps(data, indent=2, default=str))


def critical_types(extra: Optional[set] = None) -> set:
    types = set(DEFAULT_CRITICAL)
    if extra:
        types |= set(extra)
    # config overlay
    try:
        cfg_path = _home() / "config.json"
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text())
            extra_cfg = (cfg.get("alerting") or {}).get("persistent_critical_types") or []
            types |= set(extra_cfg)
    except Exception as e:
        logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    return types


def is_critical(alert_type: str, extra: Optional[set] = None) -> bool:
    return str(alert_type).upper() in {t.upper() for t in critical_types(extra)}


def _fingerprint(alert_type: str, details: Any) -> str:
    raw = f"{alert_type}|{json.dumps(details, sort_keys=True, default=str)[:400]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def record(
    alert_type: str,
    details: Any = None,
    severity: str = "CRITICAL",
    host: str = "",
    local_ip: str = "",
) -> dict:
    """Persist a critical alert. Dedupes identical open fingerprints (bumps count)."""
    if not is_critical(alert_type):
        return {"ok": False, "skipped": True, "reason": "not_critical"}

    data = _load()
    open_map = data.setdefault("open", {})
    fp = _fingerprint(alert_type, details)
    now = _now()

    if fp in open_map:
        open_map[fp]["count"] = int(open_map[fp].get("count") or 1) + 1
        open_map[fp]["last_seen"] = now
        open_map[fp]["details"] = details
        _save(data)
        return {"ok": True, "id": open_map[fp].get("id"), "fingerprint": fp, "count": open_map[fp]["count"], "updated": True}

    aid = str(uuid.uuid4())[:8]
    open_map[fp] = {
        "id": aid,
        "fingerprint": fp,
        "type": str(alert_type),
        "severity": severity,
        "details": details,
        "hostname": host,
        "local_ip": local_ip,
        "first_seen": now,
        "last_seen": now,
        "count": 1,
        "acked": False,
    }
    _save(data)
    return {"ok": True, "id": aid, "fingerprint": fp, "count": 1, "created": True}


def list_open() -> list[dict]:
    data = _load()
    items = list((data.get("open") or {}).values())
    items.sort(key=lambda x: str(x.get("last_seen") or ""), reverse=True)
    return items


def list_acked(limit: int = 50) -> list[dict]:
    data = _load()
    items = list((data.get("acked") or {}).values())
    items.sort(key=lambda x: str(x.get("acked_at") or ""), reverse=True)
    return items[:limit]


def ack(alert_id: str, actor: str = "operator") -> dict:
    data = _load()
    open_map = data.setdefault("open", {})
    acked = data.setdefault("acked", {})
    found = None
    key = None
    for k, v in open_map.items():
        if str(v.get("id")) == str(alert_id) or k == alert_id:
            found = v
            key = k
            break
    if not found:
        return {"ok": False, "error": f"open alert not found: {alert_id}"}
    found["acked"] = True
    found["acked_at"] = _now()
    found["acked_by"] = actor
    acked[key] = found
    del open_map[key]
    _save(data)
    return {"ok": True, "acked": found}


def ack_all(actor: str = "operator") -> dict:
    data = _load()
    open_map = data.setdefault("open", {})
    acked = data.setdefault("acked", {})
    n = 0
    for k, v in list(open_map.items()):
        v["acked"] = True
        v["acked_at"] = _now()
        v["acked_by"] = actor
        acked[k] = v
        del open_map[k]
        n += 1
    _save(data)
    return {"ok": True, "acked_count": n}


def status() -> dict:
    open_items = list_open()
    return {
        "ok": True,
        "open_count": len(open_items),
        "open": open_items,
        "path": str(store_path()),
        "critical_types": sorted(critical_types()),
    }


def resurface(logger=None) -> dict:
    """Log a reminder for every still-open critical alert (hunt/ops)."""
    items = list_open()
    if not items:
        return {"ok": True, "open": 0}
    if logger:
        logger.warning(
            "⚠ %s UNACKNOWLEDGED CRITICAL ALERT(S) — ack with: python3 sentinel.py critical ack <id>",
            len(items),
        )
        for it in items[:10]:
            logger.warning(
                "  CRITICAL [%s] %s x%s last=%s",
                it.get("id"),
                it.get("type"),
                it.get("count"),
                str(it.get("last_seen") or "")[:19],
            )
    return {"ok": True, "open": len(items), "items": items[:20]}
