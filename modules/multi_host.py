# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multi-host agent fleet helpers.

Coordinates:
  - central agent directory + remote_agents registry
  - per-agent API keys
  - install bundle generation
  - health / stale reporting for MSP-style multi-host pilots
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.multi_host")


def _home() -> Path:
    import os
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def status() -> dict[str, Any]:
    """Aggregate multi-host posture for dashboard / doctor / field evidence."""
    out: dict[str, Any] = {
        "ok": True,
        "ts": datetime.now(timezone.utc).isoformat(),
        "central": {},
        "registry_agents": 0,
        "agent_key_records": 0,
        "stale": [],
        "online": [],
        "hints": [],
    }
    try:
        from modules.central_agent import central_status_summary, list_stale_agents, agents_dir
        out["central"] = central_status_summary()
        stale = list_stale_agents(15)
        out["stale"] = stale.get("stale") or stale.get("agents") or []
        out["agents_dir"] = str(agents_dir())
        # list agent files
        try:
            files = list(agents_dir().glob("*.json"))
            out["central_agent_files"] = len(files)
        except Exception:
            out["central_agent_files"] = 0
    except Exception as e:
        log.debug("central status: %s", e)
        out["central_error"] = str(e)

    try:
        from modules.remote_agent import load_agents
        reg = load_agents()
        agents = reg.get("agents") or {}
        out["registry_agents"] = len(agents)
        out["registry"] = agents
        now = datetime.now()
        for k, meta in agents.items():
            last = meta.get("last_seen") or ""
            try:
                ls = datetime.fromisoformat(str(last).replace("Z", ""))
                age = (now - ls.replace(tzinfo=None)).total_seconds()
            except Exception:
                age = 999999
            row = {"id": k, **{x: meta.get(x) for x in ("hostname", "ip", "canary_count")}, "age_seconds": int(age)}
            if age < 900:
                out["online"].append(row)
            else:
                out["stale"].append(row)
    except Exception as e:
        log.debug("registry: %s", e)

    try:
        from modules.agent_keys import list_agents
        keys = list_agents()
        out["agent_key_records"] = len(keys) if isinstance(keys, list) else len(keys or {})
        out["agent_keys"] = keys
    except Exception as e:
        log.debug("keys: %s", e)

    if out["registry_agents"] == 0 and out.get("central_agent_files", 0) == 0:
        out["hints"].append("No remote agents yet — menu 23 → Build agent install bundle")
        out["hints"].append("On each host: install agent, set central URL + token/key")
    if out.get("stale"):
        out["hints"].append(f"{len(out['stale'])} agent(s) stale >15m — check connectivity")
    out["ok"] = True
    out["multi_host_ready"] = out["registry_agents"] > 0 or out.get("central_agent_files", 0) > 0
    return out


def prepare_fleet(
    central_url: Optional[str] = None,
    label: str = "pilot",
    issue_key_for: Optional[str] = None,
    master_key: Optional[str] = None,
) -> dict[str, Any]:
    """One-shot: build install bundle + optional agent API key for a host label."""
    steps: dict[str, Any] = {}
    try:
        from modules.remote_agent import build_install_bundle, ensure_agent_token, central_base_url
        url = central_url or central_base_url()
        steps["bundle"] = build_install_bundle(central_url=url, label=label)
        steps["shared_token_present"] = bool(ensure_agent_token())
    except Exception as e:
        steps["bundle"] = {"ok": False, "error": str(e)}

    if issue_key_for:
        try:
            from modules.agent_keys import issue_key
            import os
            master = master_key or os.environ.get("SENTINEL_MASTER_KEY") or ""
            # load master from config if present
            if not master:
                cfg_p = _home() / "config.json"
                if cfg_p.exists():
                    try:
                        cfg = json.loads(cfg_p.read_text())
                        master = ((cfg.get("agent") or {}).get("master_key")
                                  or (cfg.get("central") or {}).get("master_key") or "")
                    except Exception:
                        pass
            if not master:
                steps["key"] = {"ok": False, "error": "set agent.master_key in config or SENTINEL_MASTER_KEY"}
            else:
                steps["key"] = issue_key(issue_key_for, master, master)
        except Exception as e:
            steps["key"] = {"ok": False, "error": str(e)}

    return {
        "ok": bool((steps.get("bundle") or {}).get("ok", True)),
        "steps": steps,
        "next": [
            "Copy install bundle to each host",
            "Run install script; point agent at central URL",
            "python3 sentinel.py multi-host status",
            "python3 sentinel.py field-evidence",
        ],
    }
