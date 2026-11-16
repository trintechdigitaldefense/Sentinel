# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Simple agent key issue + enroll helpers for operators."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def _read_config(cfg_path: Path) -> dict:
    if not cfg_path.exists():
        return {}
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            raise ValueError("configuration root must be an object")
        return cfg
    except Exception as exc:
        raise RuntimeError(
            f"Sentinel configuration is invalid; refusing to overwrite it: {exc}"
        ) from exc


def _atomic_save_config(cfg_path: Path, cfg: dict) -> None:
    cfg_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(
        prefix=".config.", suffix=".tmp", dir=str(cfg_path.parent)
    )
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(cfg, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, cfg_path)
        os.chmod(cfg_path, 0o600)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def issue_local_agent_key(agent_id: str = "", master: Optional[str] = None) -> dict[str, Any]:
    """Issue/rotate a per-agent key; never silently repair invalid config."""
    from modules.agent_keys import issue_key

    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    cfg = _read_config(cfg_path)
    if cfg_path.exists():
        try:
            os.chmod(cfg_path, 0o600)
        except OSError:
            pass
    agent = cfg.setdefault("agent", {})
    if not isinstance(agent, dict):
        raise RuntimeError("Sentinel config agent section must be an object")
    master = master or agent.get("master_key") or ""
    if not master:
        import secrets
        master = secrets.token_urlsafe(24)
        agent["master_key"] = master
        _atomic_save_config(cfg_path, cfg)

    result = issue_key(agent_id or "", master, master)
    result["master_key_set"] = True
    if result.get("ok"):
        if result.get("rotated"):
            result["migration_note"] = (
                "The previous credential was invalidated immediately. Transfer this "
                "new key to the authorized agent and verify its check-in before closing "
                "the migration task."
            )
        result["hint"] = (
            "Configure the remote agent with this key and its HTTPS central_url; "
            "install the central CA in agent.tls_ca when using a private CA."
        )
    return result


def enroll_status() -> dict[str, Any]:
    home = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
    cfg_path = home / "config.json"
    if not cfg_path.exists():
        return {"ok": False, "enrolled": False}
    try:
        cfg = _read_config(cfg_path)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    central = cfg.get("central") or {}
    agent = cfg.get("agent") or {}
    if not isinstance(central, dict) or not isinstance(agent, dict):
        return {"ok": False, "enrolled": False, "error": "central and agent config sections must be objects"}
    enrolled = bool(
        (central.get("enabled") and central.get("api_key"))
        or (agent.get("central_url") and (agent.get("shared_token") or agent.get("api_key")))
    )
    try:
        from modules.agent_keys import list_agents
        registry = list_agents()
        legacy_agents = [
            row["agent_id"] for row in registry if row.get("migration_required")
        ]
    except Exception as exc:
        return {
            "ok": False,
            "enrolled": enrolled,
            "error": f"Could not inspect central agent-key registry safely: {exc}",
        }
    return {
        "ok": True,
        "enrolled": enrolled,
        "server_url": central.get("server_url") or agent.get("central_url"),
        "agent_id": agent.get("agent_id"),
        "has_master_key": bool(agent.get("master_key")),
        "legacy_agents": legacy_agents,
        "migration_required_count": len(legacy_agents),
        "hint": (
            "Reissue each legacy agent key and re-enroll the remote agent; "
            "legacy keys without expiry are rejected."
            if legacy_agents else
            (None if enrolled else "Issue a key (agent-key) and enroll using an HTTPS central URL.")
        ),
    }
