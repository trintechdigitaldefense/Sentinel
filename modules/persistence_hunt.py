#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 08 — Cron / systemd / RC persistence diff-since-baseline."""
from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def baseline_path() -> Path:
    return _data() / "persistence_baseline.json"

def _hash_file(p: Path) -> str:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except Exception:
        return ""

def snapshot() -> dict:
    entries = {}
    for root in ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]:
        rp = Path(root)
        if rp.is_file():
            entries[str(rp)] = {"sha256": _hash_file(rp), "type": "cron"}
        elif rp.is_dir():
            for f in sorted(rp.glob("*")):
                if f.is_file():
                    entries[str(f)] = {"sha256": _hash_file(f), "type": "cron"}
    spool = Path("/var/spool/cron/crontabs")
    if spool.is_dir():
        for f in spool.iterdir():
            if f.is_file():
                entries[str(f)] = {"sha256": _hash_file(f), "type": "cron_user"}
    for d in ["/etc/systemd/system", str(Path.home() / ".config/systemd/user")]:
        dp = Path(d)
        if dp.is_dir():
            for f in sorted(dp.glob("*.service"))[:80]:
                entries[str(f)] = {"sha256": _hash_file(f), "type": "systemd"}
    for rc in [".bashrc", ".profile", ".zshrc", ".bash_profile"]:
        p = Path.home() / rc
        if p.exists():
            entries[str(p)] = {"sha256": _hash_file(p), "type": "rc"}
    return entries

def create_baseline() -> dict:
    snap = snapshot()
    baseline_path().write_text(json.dumps({"created": datetime.now().isoformat(), "entries": snap}, indent=2))
    return {"ok": True, "count": len(snap), "path": str(baseline_path())}

def check() -> dict:
    bp = baseline_path()
    if not bp.exists():
        return {"ok": True, "needs_baseline": True, "events": [], "detail": "run persistence-baseline first"}
    try:
        base = json.loads(bp.read_text()).get("entries") or {}
    except Exception:
        return {"ok": False, "events": [], "detail": "corrupt baseline"}
    cur = snapshot()
    events = []
    for path, meta in cur.items():
        old = base.get(path)
        if not old:
            events.append({"type": "persistence", "reason": "persistence", "severity": "HIGH", "path": path, "change": "new", "entry_type": meta.get("type"), "ts": datetime.now().isoformat()})
        elif old.get("sha256") != meta.get("sha256"):
            events.append({"type": "persistence", "reason": "persistence", "severity": "HIGH", "path": path, "change": "modified", "entry_type": meta.get("type"), "ts": datetime.now().isoformat()})
    for path in base:
        if path not in cur:
            events.append({"type": "persistence", "reason": "persistence", "severity": "MEDIUM", "path": path, "change": "removed", "ts": datetime.now().isoformat()})
    return {"ok": True, "count": len(events), "events": events}
