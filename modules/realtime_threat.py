# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Real-time threat snapshot — fast host checks for dashboard / watch loop."""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RS_PATTERNS = [
    r"bash\s+-i", r"/dev/tcp/", r"nc\s+.*-e", r"ncat\s+.*-e",
    r"python[23]?\s+-c\s+[\"'].*socket", r"perl\s+-e\s+[\"'].*socket",
    r"php\s+-r\s+[\"'].*fsockopen", r"ruby\s+-rsocket", r"socat\s+.*exec",
    r"mkfifo\s+/tmp/", r"sh\s+-i",
]
RISKY_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337, 4445}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ps_lines() -> list:
    try:
        r = subprocess.run(["ps", "auxww"], capture_output=True, text=True, timeout=8)
        return (r.stdout or "").splitlines()[1:]
    except Exception:
        return []


def scan_reverse_shell_cmds() -> list:
    hits = []
    for line in _ps_lines():
        parts = line.split()
        if len(parts) < 11:
            continue
        user, pid = parts[0], parts[1]
        cmd = " ".join(parts[10:])
        for pat in RS_PATTERNS:
            if re.search(pat, cmd, re.I):
                hits.append({
                    "type": "REVERSE_SHELL_CMDLINE", "severity": "CRITICAL",
                    "pid": pid, "user": user, "pattern": pat, "cmd": cmd[:160],
                })
                break
    return hits


def scan_risky_ports() -> list:
    hits = []
    text = ""
    try:
        r = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=5)
        text = r.stdout or ""
    except Exception:
        try:
            r = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True, timeout=5)
            text = r.stdout or ""
        except Exception:
            return hits
    for p in RISKY_PORTS:
        if f":{p}" in text:
            hits.append({"type": "RISKY_LISTENER", "severity": "HIGH", "port": p,
                         "detail": f"listener on port {p}"})
    return hits


def scan_behavioral() -> list:
    try:
        from modules.behavioral_shell import scan
        raw = scan() or []
        out = []
        for h in raw[:20]:
            if isinstance(h, dict):
                out.append({"type": h.get("type") or "BEHAVIORAL", "severity": "HIGH", "detail": str(h)[:200]})
            else:
                out.append({"type": "BEHAVIORAL", "severity": "HIGH", "detail": str(h)[:200]})
        return out
    except Exception:
        return []


def open_criticals() -> list:
    try:
        from modules.critical_alerts import list_open
        return [{
            "type": it.get("type") or "CRITICAL", "severity": "CRITICAL",
            "id": it.get("id"), "count": it.get("count"), "last_seen": it.get("last_seen"),
        } for it in list_open()[:30]]
    except Exception:
        return []


def recent_high_alerts(limit: int = 15) -> list:
    ap = _data() / "alerts.log"
    if not ap.exists():
        return []
    high = []
    try:
        lines = ap.read_text(errors="ignore").splitlines()[-80:]
    except Exception:
        return []
    for ln in reversed(lines):
        try:
            a = json.loads(ln)
        except Exception:
            continue
        t = str(a.get("type") or "")
        if any(x in t.upper() for x in ("REVERSE", "CANARY", "CRITICAL", "SHELL", "SUID", "RANSOM", "BLOCK")):
            high.append({"type": t, "severity": "HIGH", "ts": a.get("timestamp") or a.get("ts"),
                         "detail": str(a.get("details") or "")[:120]})
        if len(high) >= limit:
            break
    return high


def snapshot(emit_alerts: bool = False, send_alert=None, logger=None) -> dict:
    threats = []
    threats.extend(open_criticals())
    threats.extend(scan_reverse_shell_cmds())
    threats.extend(scan_behavioral())
    threats.extend(scan_risky_ports())
    recent = recent_high_alerts(8)
    score = 0
    for t in threats:
        score += {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get((t.get("severity") or "MEDIUM").upper(), 1)
    level = "CLEAR"
    if not threats and not recent:
        level = "CLEAR"
    elif not threats and recent:
        level = "WATCH"
    elif any("SHELL" in str(t.get("type", "")).upper() or "CANARY" in str(t.get("type", "")).upper() for t in threats):
        level = "CRITICAL"
    elif threats:
        level = "HIGH" if score >= 5 else "ELEVATED"
    if emit_alerts and send_alert:
        for t in threats:
            if "SHELL" in str(t.get("type", "")).upper():
                try:
                    send_alert("REVERSE_SHELL", t, logger)
                except Exception:
                    pass
    out = {
        "ok": True, "ts": _now(), "level": level, "score": score,
        "threat_count": len(threats), "threats": threats[:40],
        "recent_high_alerts": recent, "realtime": True,
    }
    try:
        (_data() / "realtime_threat.json").write_text(json.dumps(out, indent=2, default=str))
    except Exception:
        pass
    return out


def status() -> dict:
    p = _data() / "realtime_threat.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return snapshot(emit_alerts=False)
