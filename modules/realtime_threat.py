# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Real-time threat detection — fast host snapshot for dashboard, CLI, hunt.

Detects:
  - open persistent criticals
  - reverse-shell / interactive shell command lines
  - behavioral shell heuristics
  - risky listening ports
  - canary / decoy tamper or missing files
  - deleted-binary processes (/proc/pid/exe -> (deleted))
  - suspicious LD_PRELOAD in process environment
  - recent high-severity alert log lines

Designed to finish in a few seconds for frequent polling.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

RS_PATTERNS = [
    r"bash\s+-i",
    r"/dev/tcp/",
    r"nc\s+.*-e",
    r"ncat\s+.*-e",
    r"python[23]?\s+-c\s+[\"'].*socket",
    r"perl\s+-e\s+[\"'].*socket",
    r"php\s+-r\s+[\"'].*fsockopen",
    r"ruby\s+-rsocket",
    r"socat\s+.*exec",
    r"mkfifo\s+/tmp/",
    r"sh\s+-i",
    r"dash\s+-i",
    r"zsh\s+-i",
    r"tee\s+/dev/tcp",
    r"xterm\s+-display",
]

RISKY_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337, 4445, 4443, 9001}

# Threat level → terminal ANSI + dashboard CSS class
LEVEL_STYLE = {
    "CLEAR":    {"ansi": "\033[92m", "css": "on",   "label": "CLEAR"},
    "WATCH":    {"ansi": "\033[96m", "css": "info", "label": "WATCH"},
    "ELEVATED": {"ansi": "\033[93m", "css": "elev", "label": "ELEVATED"},
    "HIGH":     {"ansi": "\033[91m", "css": "warn", "label": "HIGH"},
    "CRITICAL": {"ansi": "\033[95m", "css": "bad",  "label": "CRITICAL"},
    "UNKNOWN":  {"ansi": "\033[90m", "css": "off",  "label": "UNKNOWN"},
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

SEVERITY_ANSI = {
    "CRITICAL": "\033[95m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[92m",
}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def level_style(level: str) -> dict:
    return LEVEL_STYLE.get((level or "UNKNOWN").upper(), LEVEL_STYLE["UNKNOWN"])


def level_ansi(level: str, *, bold: bool = True) -> str:
    st = level_style(level)
    return f"{st['ansi']}{_BOLD if bold else ''}{st['label']}{_RESET}"


def severity_ansi(sev: str) -> str:
    s = (sev or "MEDIUM").upper()
    c = SEVERITY_ANSI.get(s, "\033[0m")
    return f"{c}{s}{_RESET}"


def format_monitor_line(snap: dict) -> str:
    level = str(snap.get("level") or "CLEAR")
    ts = str(snap.get("ts") or "")[:19]
    return (
        f"{ts}  level={level_ansi(level)}  "
        f"threats={snap.get('threat_count', 0)}  score={snap.get('score', 0)}"
    )


def format_threat_line(t: dict) -> str:
    sev = severity_ansi(str(t.get("severity") or ""))
    typ = t.get("type") or ""
    det = str(t.get("cmd") or t.get("detail") or t.get("id") or t.get("port") or t.get("path") or "")[:80]
    return f"   · {sev} {typ} {det}"


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
                    "type": "REVERSE_SHELL_CMDLINE",
                    "severity": "CRITICAL",
                    "confidence": "medium",
                    "pid": pid,
                    "user": user,
                    "pattern": pat,
                    "cmd": cmd[:160],
                })
                break
    return hits


def scan_deleted_exe() -> list:
    """Processes whose executable was deleted from disk (common malware hide)."""
    hits = []
    proc = Path("/proc")
    if not proc.exists():
        return hits
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()]
    except Exception:
        return hits
    for p in pids[:400]:
        exe = p / "exe"
        try:
            target = os.readlink(str(exe))
        except Exception:
            continue
        if "(deleted)" in target:
            cmdline = ""
            try:
                cmdline = (p / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")[:120]
            except Exception:
                pass
            hits.append({
                "type": "DELETED_EXE",
                "severity": "HIGH",
                "confidence": "medium",
                "pid": p.name,
                "path": target[:160],
                "cmd": cmdline,
            })
    return hits


def scan_ld_preload() -> list:
    hits = []
    proc = Path("/proc")
    if not proc.exists():
        return hits
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()]
    except Exception:
        return hits
    for p in pids[:300]:
        env = p / "environ"
        try:
            raw = env.read_bytes()
        except Exception:
            continue
        if b"LD_PRELOAD=" not in raw:
            continue
        for part in raw.split(b"\x00"):
            if part.startswith(b"LD_PRELOAD=") and len(part) > 11:
                val = part.decode("utf-8", "replace")[11:]
                if val.strip():
                    hits.append({
                        "type": "LD_PRELOAD",
                        "severity": "HIGH",
                        "pid": p.name,
                        "detail": val[:160],
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
            hits.append({
                "type": "RISKY_LISTENER",
                "severity": "HIGH",
                "confidence": "low",
                "port": p,
                "detail": f"listener on port {p}",
            })
    return hits


def scan_behavioral() -> list:
    try:
        from modules.behavioral_shell import scan
        raw = scan() or []
        out = []
        for h in raw[:20]:
            if isinstance(h, dict):
                out.append({
                    "type": h.get("type") or "BEHAVIORAL",
                    "severity": "HIGH",
                    "detail": str(h)[:200],
                })
            else:
                out.append({"type": "BEHAVIORAL", "severity": "HIGH", "detail": str(h)[:200]})
        return out
    except Exception:
        return []


def scan_canaries() -> list:
    """Check only *tracked* canary/decoy paths for missing or empty files.

    Does not invent home paths — avoids false CRITICAL when deception was never deployed.
    """
    hits = []
    dec = _data() / "deception_artifacts"
    tracker = dec / "config.json"
    paths: list = []
    if tracker.exists():
        try:
            cfg = json.loads(tracker.read_text())
            if isinstance(cfg, dict):
                for k in ("files", "canaries", "artifacts", "paths", "deployed", "decoys"):
                    v = cfg.get(k)
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, str):
                                paths.append(item)
                            elif isinstance(item, dict):
                                paths.append(
                                    item.get("path") or item.get("file") or item.get("target") or ""
                                )
                # flat path values
                for k, v in cfg.items():
                    if isinstance(v, str) and (v.startswith("/") or v.startswith("~")):
                        paths.append(v)
        except Exception:
            pass
    # Files physically under deception_artifacts (except tracker)
    if dec.exists():
        try:
            for f in dec.rglob("*"):
                if f.is_file() and f.name != "config.json":
                    paths.append(str(f))
        except Exception:
            pass
    if not paths:
        return hits  # nothing deployed → no canary noise
    seen = set()
    for p in paths:
        if not p or p in seen:
            continue
        seen.add(p)
        fp = Path(p).expanduser()
        if not fp.exists():
            hits.append({
                "type": "CANARY_MISSING",
                "severity": "CRITICAL",
                "path": str(fp),
                "detail": "tracked canary/decoy missing",
            })
            continue
        try:
            if fp.is_file() and fp.stat().st_size == 0:
                hits.append({
                    "type": "CANARY_EMPTY",
                    "severity": "HIGH",
                    "path": str(fp),
                    "detail": "tracked canary empty",
                })
        except Exception:
            pass
    return hits[:25]


def open_criticals() -> list:
    try:
        from modules.critical_alerts import list_open
        return [{
            "type": it.get("type") or "CRITICAL",
            "severity": "CRITICAL",
            "id": it.get("id"),
            "count": it.get("count"),
            "last_seen": it.get("last_seen"),
        } for it in list_open()[:30]]
    except Exception:
        return []


def recent_high_alerts(limit: int = 15) -> list:
    ap = _data() / "alerts.log"
    if not ap.exists():
        return []
    high = []
    try:
        lines = ap.read_text(errors="ignore").splitlines()[-100:]
    except Exception:
        return []
    for ln in reversed(lines):
        try:
            a = json.loads(ln)
        except Exception:
            continue
        t = str(a.get("type") or "")
        if any(x in t.upper() for x in ("REVERSE", "CANARY", "CRITICAL", "SHELL", "SUID", "RANSOM", "BLOCK", "DELETED")):
            high.append({
                "type": t,
                "severity": "HIGH",
                "ts": a.get("timestamp") or a.get("ts"),
                "detail": str(a.get("details") or "")[:120],
            })
        if len(high) >= limit:
            break
    return high


def _score_level(threats: list, recent: list) -> tuple:
    score = 0
    for t in threats:
        score += {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(
            (t.get("severity") or "MEDIUM").upper(), 1
        )
    if not threats and not recent:
        return "CLEAR", score
    if not threats and recent:
        return "WATCH", score
    types = " ".join(str(t.get("type") or "") for t in threats).upper()
    if any(x in types for x in ("SHELL", "CANARY", "REVERSE")):
        return "CRITICAL", score
    if score >= 5:
        return "HIGH", score
    return "ELEVATED", score


def snapshot(
    emit_alerts: bool = False,
    send_alert: Optional[Callable] = None,
    logger=None,
) -> dict:
    """Full real-time threat detection snapshot."""
    threats: list = []
    threats.extend(open_criticals())
    threats.extend(scan_reverse_shell_cmds())
    threats.extend(scan_behavioral())
    threats.extend(scan_risky_ports())
    threats.extend(scan_deleted_exe())
    threats.extend(scan_ld_preload())
    threats.extend(scan_canaries())
    recent = recent_high_alerts(8)
    level, score = _score_level(threats, recent)

    if emit_alerts:
        # Always record criticals into persistent store
        try:
            from modules.critical_alerts import record
            for t in threats:
                typ = str(t.get("type") or "")
                if t.get("severity") == "CRITICAL" or any(
                    x in typ.upper() for x in ("SHELL", "CANARY", "REVERSE")
                ):
                    record(typ or "REALTIME_CRITICAL", t, host=None)
        except Exception:
            pass
        if send_alert:
            for t in threats:
                typ = str(t.get("type") or "")
                if "SHELL" in typ.upper() or typ == "REVERSE_SHELL_CMDLINE":
                    try:
                        send_alert("REVERSE_SHELL", t, logger)
                    except Exception:
                        pass
                elif "CANARY" in typ.upper():
                    try:
                        send_alert("CANARY_TRIGGERED", t, logger)
                    except Exception:
                        pass
                elif typ == "DELETED_EXE":
                    try:
                        send_alert("DELETED_EXE", t, logger)
                    except Exception:
                        pass

    out = {
        "ok": True,
        "ts": _now(),
        "level": level,
        "score": score,
        "threat_count": len(threats),
        "threats": threats[:50],
        "recent_high_alerts": recent,
        "realtime": True,
        "disclaimer": "Heuristics are leads, not proof of compromise.",
        "detectors": [
            "criticals", "reverse_shell", "behavioral", "risky_ports",
            "deleted_exe", "ld_preload", "canaries",
        ],
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
