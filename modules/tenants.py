# © 2026 TrinTech Digital Defense — authorized defensive use only
"""MSP multi-tenant registry (Phase 12 foundation).

This is NOT a full cloud SIEM. It is a local/MSP tenant roster so agents,
cases, and central summaries can be tagged with a client/tenant id.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _path() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d / "tenants.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load() -> dict:
    p = _path()
    if not p.exists():
        return {"tenants": [], "default_tenant_id": ""}
    try:
        data = json.loads(p.read_text())
        if isinstance(data, list):
            return {"tenants": data, "default_tenant_id": data[0]["id"] if data else ""}
        return data
    except Exception:
        return {"tenants": [], "default_tenant_id": ""}


def save(data: dict) -> None:
    _path().write_text(json.dumps(data, indent=2))


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "tenant").lower()).strip("-")
    return (s or "tenant")[:40]


def create_tenant(name: str, notes: str = "") -> dict:
    data = load()
    tid = f"tnt-{_slug(name)}-{secrets.token_hex(2)}"
    row = {
        "id": tid,
        "name": (name or "").strip() or tid,
        "notes": notes or "",
        "created_at": _now(),
        "active": True,
    }
    data.setdefault("tenants", []).append(row)
    if not data.get("default_tenant_id"):
        data["default_tenant_id"] = tid
    save(data)
    return {"ok": True, "tenant": row}


def list_tenants(active_only: bool = True) -> list[dict]:
    rows = load().get("tenants") or []
    if active_only:
        rows = [r for r in rows if r.get("active", True)]
    return rows


def set_default(tenant_id: str) -> dict:
    data = load()
    ids = {t["id"] for t in data.get("tenants") or []}
    if tenant_id not in ids:
        return {"ok": False, "error": "tenant not found"}
    data["default_tenant_id"] = tenant_id
    save(data)
    return {"ok": True, "default_tenant_id": tenant_id}


def get_default() -> Optional[str]:
    data = load()
    return data.get("default_tenant_id") or (data.get("tenants") or [{}])[0].get("id")


def deactivate(tenant_id: str) -> dict:
    data = load()
    found = False
    for t in data.get("tenants") or []:
        if t.get("id") == tenant_id:
            t["active"] = False
            found = True
    if not found:
        return {"ok": False, "error": "tenant not found"}
    save(data)
    return {"ok": True, "tenant_id": tenant_id, "active": False}
