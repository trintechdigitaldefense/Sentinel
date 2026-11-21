# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Per-agent API key issue / verify / revoke for central MSP mode.

Phase 5: added resolve_agent_id() for key-only auth without trusting client headers.
"""
from __future__ import annotations
import logging

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
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
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("agents", {}), dict):
            raise ValueError("registry must contain an agents object")
        if any(not isinstance(record, dict) for record in data["agents"].values()):
            raise ValueError("every agent registry record must be an object")
        return data
    except Exception as exc:
        raise RuntimeError(f"agent key registry is unreadable; refusing to reset it: {exc}") from exc


def _save(data: dict) -> None:
    p = _keys_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    fd, name = tempfile.mkstemp(prefix=".agent_keys.", suffix=".tmp", dir=str(p.parent))
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _not_expired(record: dict) -> bool:
    if not isinstance(record, dict):
        return False
    value = record.get("expires_at")
    if not value:
        return False
    try:
        expires = datetime.fromisoformat(str(value))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < expires
    except (TypeError, ValueError):
        return False


def issue_key(agent_id: str, master_key: str, provided_master: str, ttl_seconds: int = 2592000) -> dict:
    if (
        not isinstance(master_key, str)
        or not isinstance(provided_master, str)
        or not master_key.strip()
        or not provided_master.strip()
    ):
        return {"ok": False, "error": "invalid master key"}
    if not secrets.compare_digest(master_key, provided_master):
        return {"ok": False, "error": "invalid master key"}
    if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 31536000:
        return {"ok": False, "error": "ttl_seconds must be between 60 seconds and 365 days"}
    agent_id = (agent_id or "").strip() or f"agent-{secrets.token_hex(4)}"
    raw = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    data = _load()
    previous = (data.setdefault("agents", {})).get(agent_id)
    legacy_migration = isinstance(previous, dict) and not previous.get("expires_at")
    rotated = isinstance(previous, dict)
    data["agents"][agent_id] = {
        "key_hash": _hash(raw),
        "created": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "revoked": False,
    }
    _save(data)
    return {
        "ok": True, "agent_id": agent_id, "api_key": raw,
        "expires_at": expires_at, "rotated": rotated,
        "legacy_migration": legacy_migration,
    }


def verify_key(agent_id: str, api_key: str) -> bool:
    if not api_key:
        return False
    data = _load()
    rec = (data.get("agents") or {}).get(agent_id or "")
    if not rec or rec.get("revoked") or not _not_expired(rec):
        return False
    return secrets.compare_digest(rec.get("key_hash") or "", _hash(api_key))


def resolve_agent_id(api_key: str) -> Optional[str]:
    """Return agent_id for a valid non-revoked key, or None.

    Used when the client does not (or must not) supply X-Client-Id.
    Never trusts a client-supplied agent_id alone.
    """
    if not api_key:
        return None
    h = _hash(api_key)
    data = _load()
    for aid, r in (data.get("agents") or {}).items():
        if r.get("revoked") or not _not_expired(r):
            continue
        if secrets.compare_digest(r.get("key_hash") or "", h):
            return aid
    return None


def revoke(agent_id: str, master_key: str, provided_master: str) -> dict:
    if not secrets.compare_digest(master_key, provided_master):
        return {"ok": False, "error": "invalid master key"}
    data = _load()
    if agent_id not in (data.get("agents") or {}):
        return {"ok": False, "error": "unknown agent"}
    data["agents"][agent_id]["revoked"] = True
    data["agents"][agent_id]["revoked_at"] = datetime.now(timezone.utc).isoformat()
    _save(data)
    return {"ok": True, "agent_id": agent_id, "revoked": True}


def list_agents() -> list:
    data = _load()
    out = []
    for aid, r in (data.get("agents") or {}).items():
        expires_at = r.get("expires_at")
        expiry_valid = False
        if expires_at:
            try:
                datetime.fromisoformat(str(expires_at))
                expiry_valid = True
            except (TypeError, ValueError):
                expiry_valid = False
        revoked = bool(r.get("revoked"))
        expired = not _not_expired(r)
        out.append({
            "agent_id": aid,
            "created": r.get("created"),
            "expires_at": expires_at,
            "expired": expired,
            "legacy": not bool(expires_at),
            "invalid_expiry": bool(expires_at) and not expiry_valid,
            "migration_required": not revoked and (not expiry_valid or expired),
            "revoked": revoked,
            "revoked_at": r.get("revoked_at"),
        })
    return out
