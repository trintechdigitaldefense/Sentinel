#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 05 — USB / removable-media watcher."""
from __future__ import annotations
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def enabled() -> bool:
    return bool((_cfg().get("usb_watch") is True) or ((_cfg().get("detection") or {}).get("usb_watch")))

def _run(cmd) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout or ""
    except Exception:
        return ""

def scan_usb() -> list:
    events = []
    out = _run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT,TRAN,RM,SIZE,MODEL,SERIAL"])
    try:
        data = json.loads(out) if out else {}
    except Exception:
        data = {}
    def walk(nodes, parent_tran=None):
        for n in nodes or []:
            tran = n.get("tran") or parent_tran
            rm = n.get("rm")
            mp = n.get("mountpoint")
            is_usb = (tran == "usb") or (rm in (1, True, "1"))
            if is_usb and mp:
                events.append({
                    "type": "usb_mount",
                    "reason": "usb",
                    "device": n.get("name"),
                    "mountpoint": mp,
                    "model": n.get("model"),
                    "serial": n.get("serial"),
                    "size": n.get("size"),
                    "tran": tran,
                    "ts": datetime.now().isoformat(),
                })
            walk(n.get("children") or [], tran)
    walk(data.get("blockdevices") or [])
    return events

def check() -> dict:
    if not enabled():
        return {"ok": True, "enabled": False, "events": [], "detail": "usb_watch off — set usb_watch: true in config"}
    events = scan_usb()
    return {"ok": True, "enabled": True, "count": len(events), "events": events}
