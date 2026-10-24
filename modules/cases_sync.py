# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Push local open cases to central (Phase 9 MSP read model)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def sync_open_cases_to_central(
    central_url: Optional[str] = None,
    agent_key: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """POST open case summaries to central /v1/cases/sync."""
    from modules.msp_digest import collect_open_cases

    cfg = _cfg()
    central = cfg.get("central") or {}
    url = (central_url or central.get("server_url") or "").rstrip("/")
    key = agent_key or central.get("api_key") or (cfg.get("agent") or {}).get("shared_token") or ""
    if not url or not key:
        return {"ok": False, "error": "central_url and agent key required"}
    rows = collect_open_cases(limit=limit)
    payload = {
        "cases": [
            {
                "id": c.get("id"),
                "title": c.get("title"),
                "status": c.get("status"),
                "severity": c.get("severity"),
                "assignee": c.get("assignee"),
                "updated_at": c.get("updated_at"),
                "source": c.get("source"),
            }
            for c in rows
        ]
    }
    endpoint = f"{url}/v1/cases/sync"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Key": key,
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return {"ok": True, "endpoint": endpoint, "count": len(rows), "response": parsed}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}", "detail": e.read().decode()[:500]}
    except Exception as e:
        return {"ok": False, "error": str(e)}
