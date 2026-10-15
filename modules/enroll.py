# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Agent enrollment to central server (per-agent keys)."""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path


def enroll(server_url: str, master_or_key: str, agent_id: str = "") -> dict:
    server_url = (server_url or "").rstrip("/")
    if server_url.startswith("http://") and not os.environ.get("SENTINEL_ALLOW_HTTP"):
        return {
            "ok": False,
            "error": "Enrollment requires HTTPS. Use https://... or set SENTINEL_ALLOW_HTTP=1 for lab only.",
        }
    # Prefer remote enroll endpoint
    body = json.dumps({"agent_id": agent_id or os.uname().nodename if hasattr(os, "uname") else "agent"}).encode()
    req = urllib.request.Request(
        server_url + "/v1/enroll",
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": master_or_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read().decode())
    except Exception as e:
        # Offline / lab: issue locally if central dir shared
        try:
            from modules.agent_keys import issue_key
            resp = issue_key(agent_id or "local", master_or_key, master_or_key)
        except Exception:
            return {"ok": False, "error": str(e)}

    if not resp.get("ok"):
        return resp

    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            cfg = {}
    cfg.setdefault("central", {})
    cfg["central"]["enabled"] = True
    cfg["central"]["server_url"] = server_url
    cfg["central"]["api_key"] = resp.get("api_key") or master_or_key
    cfg.setdefault("agent", {})
    cfg["agent"]["agent_id"] = resp.get("agent_id") or agent_id
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(cfg_path, 0o600)
    except Exception:
        pass
    return {
        "ok": True,
        "agent_id": cfg["agent"]["agent_id"],
        "server_url": server_url,
        "api_key_set": True,
    }
