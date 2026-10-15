# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Per-agent API key issue / verify / revoke for central MSP mode."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional


def _central_dir() -> Path:
    return Path(os.environ.get("SENTINEL_CENTRAL_DIR", Path.home() / ".sentinel-central"))


def _keys_path() -> Path:
    return _central_dir() / "agent_keys.json"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _load() -> dict:
    p = _keys_path()
    if not p.exists():
        return {"agents": {}}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"agents": {}}


def _save(data: dict) -> None:
    p = _keys_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def issue_key(agent_id: str, master_key: str, provided_master: str) -> dict:
    if not secrets.compare_digest(master_key, provided_master):
        return {"ok": False, "error": "invalid master key"}
    agent_id = (agent_id or "").strip() or f"agent-{secrets.token_hex(4)}"
    raw = secrets.token_urlsafe(32)
    data = _load()
    data.setdefault("agents", {})[agent_id] = {
        "key_hash": _hash(raw),
        "created": datetime.now().isoformat(),
        "revoked": False,
    }
    _save(data)
    return {"ok": True, "agent_id": agent_id, "api_key": raw}


def verify_key(agent_id: str, api_key: str) -> bool:
    data = _load()
    rec = (data.get("agents") or {}).get(agent_id or "")
    if not rec or rec.get("revoked"):
        # also allow lookup by scanning hashes if agent_id missing
        if not agent_id:
            h = _hash(api_key)
            for aid, r in (data.get("agents") or {}).items():
                if not r.get("revoked") and r.get("key_hash") == h:
                    return True
            return False
        return False
    return secrets.compare_digest(rec.get("key_hash") or "", _hash(api_key))


def revoke(agent_id: str, master_key: str, provided_master: str) -> dict:
    if not secrets.compare_digest(master_key, provided_master):
        return {"ok": False, "error": "invalid master key"}
    data = _load()
    if agent_id not in (data.get("agents") or {}):
        return {"ok": False, "error": "unknown agent"}
    data["agents"][agent_id]["revoked"] = True
    data["agents"][agent_id]["revoked_at"] = datetime.now().isoformat()
    _save(data)
    return {"ok": True, "agent_id": agent_id, "revoked": True}


def list_agents() -> list:
    data = _load()
    out = []
    for aid, r in (data.get("agents") or {}).items():
        out.append({
            "agent_id": aid,
            "created": r.get("created"),
            "revoked": bool(r.get("revoked")),
            "revoked_at": r.get("revoked_at"),
        })
    return out
