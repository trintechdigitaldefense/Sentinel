#!/usr/bin/env python3
"""FEATURE 06 — SMB/RDP anomaly / lateral movement heuristics."""
from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def _auth_log_paths():
    for p in ("/var/log/auth.log", "/var/log/secure", "/var/log/messages"):
        if Path(p).exists():
            yield p

def scan_rdp_odd_hours() -> list:
    alerts = []
    for path in _auth_log_paths():
        try:
            lines = Path(path).read_text(errors="ignore").splitlines()[-400:]
        except Exception:
            continue
        for line in lines:
            if "Accepted" in line or "session opened" in line:
                m = re.search(r"\s(\d{2}):(\d{2}):(\d{2})\s", line)
                if m:
                    h = int(m.group(1))
                    if 0 <= h < 5:
                        alerts.append({
                            "type": "lateral",
                            "reason": "rdp",
                            "severity": "HIGH",
                            "detail": line.strip()[:200],
                            "hour": h,
                            "ts": datetime.now().isoformat(),
                        })
    seen = set()
    out = []
    for a in alerts:
        key = a["detail"][:80]
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out[:20]

def scan_spray_accounts() -> list:
    fails = defaultdict(int)
    for path in _auth_log_paths():
        try:
            lines = Path(path).read_text(errors="ignore").splitlines()[-500:]
        except Exception:
            continue
        for line in lines:
            if "Failed password" in line or "authentication failure" in line.lower():
                um = re.search(r"for\s+(\S+)", line)
                user = um.group(1) if um else "unknown"
                fails[user] += 1
    alerts = []
    multi = {u: n for u, n in fails.items() if n >= 5}
    if len(multi) >= 3:
        alerts.append({
            "type": "lateral",
            "reason": "ssh_bruteforce",
            "severity": "HIGH",
            "detail": f"spray-like failures across {len(multi)} users: {dict(list(multi.items())[:8])}",
            "ts": datetime.now().isoformat(),
        })
    return alerts

def check() -> dict:
    events = scan_rdp_odd_hours() + scan_spray_accounts()
    return {"ok": True, "count": len(events), "events": events}
