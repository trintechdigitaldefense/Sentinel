#!/usr/bin/env python3
"""FEATURE 09 — Honey-credential auth monitor."""
from __future__ import annotations
import json
import os
import re
from datetime import datetime
from pathlib import Path

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def load_honey_usernames() -> set:
    names = set()
    cfg_p = _home() / "config.json"
    if cfg_p.exists():
        try:
            c = json.loads(cfg_p.read_text())
            for u in (c.get("honey_usernames") or []):
                names.add(str(u).lower())
            mir = c.get("mirage") or {}
            for u in (mir.get("honey_usernames") or []):
                names.add(str(u).lower())
        except Exception:
            pass
    decoy = _data() / "deception_artifacts"
    if decoy.exists():
        for f in decoy.rglob("*"):
            if not f.is_file():
                continue
            try:
                text = f.read_text(errors="ignore")[:4000]
            except Exception:
                continue
            for m in re.findall(r"(?:user(?:name)?|DB_USER|ADMIN)\s*[=:]\s*([A-Za-z0-9._-]{3,32})", text, re.I):
                names.add(m.lower())
            for hint in ("admin", "trintech_admin", "backup_admin", "svc_backup", "aws_admin"):
                if hint in text.lower():
                    names.add(hint)
    names.update({"honeyadmin", "canary_admin", "trintech_decoy", "decoy_admin"})
    return {n for n in names if n and len(n) >= 3}

def _auth_paths():
    for p in ("/var/log/auth.log", "/var/log/secure", "/var/log/messages"):
        if Path(p).exists():
            yield Path(p)

def check() -> dict:
    honeys = load_honey_usernames()
    events = []
    for path in _auth_paths():
        try:
            lines = path.read_text(errors="ignore").splitlines()[-500:]
        except Exception:
            continue
        for line in lines:
            low = line.lower()
            if not any(x in low for x in ("failed", "invalid", "accepted", "authentication failure", "user not known")):
                continue
            for user in honeys:
                if re.search(rf"\b{re.escape(user)}\b", low):
                    events.append({
                        "type": "honey_auth",
                        "reason": "honey_auth",
                        "severity": "CRITICAL",
                        "username": user,
                        "detail": line.strip()[:220],
                        "source": str(path),
                        "ts": datetime.now().isoformat(),
                    })
                    break
    seen = set()
    out = []
    for e in events:
        k = e["detail"][:100]
        if k not in seen:
            seen.add(k)
            out.append(e)
    return {"ok": True, "honey_usernames": sorted(honeys)[:40], "count": len(out), "events": out[:30]}
