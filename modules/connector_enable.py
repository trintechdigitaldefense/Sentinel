# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Enable / test read-only connectors and optional auto-case fetch (Phase 10)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def _cfg_path() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"


def load_config() -> dict:
    p = _cfg_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    p = _cfg_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def enable_wazuh(
    url: str,
    user: str,
    password: str,
    verify_tls: bool = True,
    agent_id: str = "",
) -> dict:
    """Write Wazuh connector settings into config.json (read-only credentials)."""
    cfg = load_config()
    connectors = cfg.setdefault("connectors", {})
    connectors["wazuh"] = {
        "enabled": True,
        "url": (url or "").rstrip("/"),
        "user": user or "",
        "password": password or "",
        "verify_tls": bool(verify_tls),
        "agent_id": agent_id or "",
    }
    save_config(cfg)
    return {"ok": True, "connector": "wazuh", "url": connectors["wazuh"]["url"]}


def enable_local(auto_case: bool = True) -> dict:
    cfg = load_config()
    connectors = cfg.setdefault("connectors", {})
    connectors["sentinel_local"] = {"enabled": True, "auto_case": bool(auto_case)}
    save_config(cfg)
    return {"ok": True, "connector": "sentinel_local", "auto_case": auto_case}


def health(source: str = "sentinel_local") -> dict:
    from modules.connectors import get_connector

    cfg = load_config().get("connectors", {}).get(source) or {}
    conn = get_connector(source, cfg)
    h = conn.health_check()
    return h.to_dict() if hasattr(h, "to_dict") else dict(h)


def fetch_and_maybe_case(
    source: str = "sentinel_local", limit: int = 20, auto_case: Optional[bool] = None
) -> dict:
    from modules.connectors import get_connector

    cfg_all = load_config().get("connectors", {})
    cfg = dict(cfg_all.get(source) or {})
    if auto_case is None:
        auto_case = bool(cfg.get("auto_case", source == "sentinel_local"))
    conn = get_connector(source, cfg)
    alerts, nxt = conn.fetch_events(limit=limit)
    opened = []
    if auto_case:
        try:
            from modules.case_hooks import maybe_open_case_from_normalized

            for a in alerts:
                d = a.to_dict() if hasattr(a, "to_dict") else dict(a)
                r = maybe_open_case_from_normalized(d)
                if r and r.get("ok"):
                    opened.append(r["case"]["id"])
        except Exception as e:
            return {"ok": False, "error": str(e), "count": len(alerts), "next_cursor": nxt}
    return {
        "ok": True,
        "source": source,
        "count": len(alerts),
        "cases_opened": opened,
        "next_cursor": nxt,
        "alerts": [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in alerts[:limit]],
    }
