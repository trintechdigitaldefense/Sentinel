# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Simple agent key issue + enroll helpers for operators."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional


def issue_local_agent_key(agent_id: str = "", master: Optional[str] = None) -> dict[str, Any]:
    """Issue a per-agent API key using config agent.master_key or a generated master."""
    from modules.agent_keys import issue_key

    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            cfg = {}
    agent = cfg.setdefault("agent", {})
    master = master or agent.get("master_key") or ""
    if not master:
        import secrets
        master = secrets.token_urlsafe(24)
        agent["master_key"] = master
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(cfg, indent=2))
        try:
            os.chmod(cfg_path, 0o600)
        except Exception:
            pass
    r = issue_key(agent_id or "", master, master)
    r["master_key_set"] = True
    r["hint"] = (
        "On the remote host run: "
        "python3 sentinel.py enroll --server http://CENTRAL:8743 --key <api_key>"
    )
    return r


def enroll_status() -> dict[str, Any]:
    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    if not cfg_path.exists():
        return {"ok": False, "enrolled": False}
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return {"ok": False, "error": str(e)}
    central = cfg.get("central") or {}
    agent = cfg.get("agent") or {}
    enrolled = bool(
        central.get("enabled")
        and (central.get("api_key") or agent.get("shared_token") or agent.get("api_key"))
    )
    return {
        "ok": True,
        "enrolled": enrolled,
        "server_url": central.get("server_url") or agent.get("central_url"),
        "agent_id": agent.get("agent_id"),
        "has_master_key": bool(agent.get("master_key")),
        "hint": None if enrolled else "Issue a key (agent-key) then: enroll --server URL --key KEY",
    }
