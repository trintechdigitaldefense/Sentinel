#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 14 — New-device-on-network radar."""
from __future__ import annotations
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def known_path() -> Path:
    return _data() / "known_devices.json"

def load_known() -> dict:
    p = known_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}

def save_known(data: dict) -> None:
    known_path().write_text(json.dumps(data, indent=2))

def _run(cmd) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return r.stdout or ""
    except Exception:
        return ""

def discover() -> list:
    devices = []
    out = _run(["ip", "neigh", "show"]) or _run(["arp", "-an"])
    for line in out.splitlines():
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        mac = (mac_m.group(1).lower() if mac_m else "unknown")
        if ip.endswith(".0") or ip.endswith(".255"):
            continue
        devices.append({"ip": ip, "mac": mac, "raw": line.strip()[:120]})
    seen = {}
    for d in devices:
        seen[d["ip"]] = d
    return list(seen.values())

def check(auto_promote_days: int = 7) -> dict:
    known = load_known()
    now = datetime.now()
    found = discover()
    new_devices = []
    for d in found:
        key = d["mac"] if d["mac"] != "unknown" else d["ip"]
        if key not in known and d["ip"] not in known:
            entry = {**d, "first_seen": now.isoformat(), "last_seen": now.isoformat(), "status": "new"}
            new_devices.append(entry)
            known[key] = entry
        else:
            k = key if key in known else d["ip"]
            known[k]["last_seen"] = now.isoformat()
            try:
                fs = datetime.fromisoformat(str(known[k].get("first_seen", now.isoformat())))
                if known[k].get("status") == "new" and (now - fs).days >= auto_promote_days:
                    known[k]["status"] = "known"
            except Exception:
                pass
    save_known(known)
    events = [{
        "type": "new_device", "reason": "new_device", "severity": "MEDIUM",
        "ip": d.get("ip"), "mac": d.get("mac"),
        "detail": f"Unknown device {d.get('ip')} mac={d.get('mac')}",
        "ts": now.isoformat(),
    } for d in new_devices]
    return {"ok": True, "scanned": len(found), "known_total": len(known),
            "new_count": len(new_devices), "events": events, "new_devices": new_devices}

def approve(key: str) -> dict:
    known = load_known()
    if key in known:
        known[key]["status"] = "known"
        known[key]["approved"] = datetime.now().isoformat()
        save_known(known)
        return {"ok": True, "key": key}
    for k, v in known.items():
        if v.get("ip") == key or v.get("mac") == key:
            v["status"] = "known"
            v["approved"] = datetime.now().isoformat()
            save_known(known)
            return {"ok": True, "key": k}
    return {"ok": False, "error": "not found"}
