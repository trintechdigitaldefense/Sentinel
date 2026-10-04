#!/usr/bin/env python3
"""Sentinel Phase 4 — Hard to Copy (compact)"""
from __future__ import annotations
import json, os, socket, subprocess, shutil, zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
def _data() -> Path:
    d = _home() / "data"; d.mkdir(parents=True, exist_ok=True); return d
def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: pass
    return {}
def ensure_phase4_defaults(config=None):
    c = config if config is not None else _cfg()
    p4 = c.setdefault("phase4", {})
    p4.setdefault("behavioral", {"enabled": True})
    p4.setdefault("caribbean_pack", {"enabled": True})
    p4.setdefault("playbooks", {"enabled": True})
    p4.setdefault("offline", {"enabled": True, "queue_max": 500})
    return c
def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return str(e)
def collect_behavior_snapshot():
    procs, users = Counter(), Counter()
    for line in _run(["ps", "auxww", "--no-headers"]).splitlines():
        parts = line.split()
        if len(parts) < 11: continue
        users[parts[0]] += 1
        procs[parts[10].split("/")[-1][:40]] += 1
    ports = set()
    ss = _run(["ss", "-tuln"]) or _run(["netstat", "-tuln"])
    for line in ss.splitlines():
        for token in line.split():
            if ":" in token:
                try:
                    port = token.rsplit(":", 1)[-1]
                    if port.isdigit(): ports.add(int(port))
                except Exception: pass
    return {"time": datetime.now().isoformat(), "host": socket.gethostname(),
            "top_procs": dict(procs.most_common(40)), "users": dict(users),
            "ports": sorted(ports)[:80], "proc_count": sum(procs.values())}
def baseline_build(config=None):
    snap = collect_behavior_snapshot()
    out = {"created": datetime.now().isoformat(), "snapshot": snap,
           "learned_procs": sorted(snap["top_procs"]), "learned_users": sorted(snap["users"]),
           "learned_ports": sorted(snap["ports"])}
    path = _data() / "behavioral_baseline.json"
    path.write_text(json.dumps(out, indent=2))
    return {"ok": True, "file": str(path), "procs": len(out["learned_procs"]), "ports": len(out["learned_ports"])}
def baseline_check(config=None):
    path = _data() / "behavioral_baseline.json"
    if not path.exists():
        return {"ok": False, "error": "no baseline — run: sentinel baseline", "anomalies": []}
    base = json.loads(path.read_text())
    now = collect_behavior_snapshot()
    lp, lu, lports = set(base.get("learned_procs") or []), set(base.get("learned_users") or []), set(base.get("learned_ports") or [])
    anomalies = []
    np_ = [p for p in now["top_procs"] if p not in lp]
    nu = [u for u in now["users"] if u not in lu]
    nports = [p for p in now["ports"] if p not in lports]
    if np_: anomalies.append({"type": "new_processes", "items": np_[:15]})
    if nu: anomalies.append({"type": "new_users", "items": nu})
    if nports: anomalies.append({"type": "new_ports", "items": nports[:20]})
    return {"ok": True, "baseline_age": base.get("created"), "anomaly_count": len(anomalies),
            "anomalies": anomalies, "current_proc_count": now["proc_count"]}
CARIBBEAN_PORTS = [4444, 5555, 6666, 1337, 31337, 4445, 8888, 9999, 1234, 7777]
def caribbean_scan(config=None, run_cmd=None):
    findings = []
    ss = _run(["ss", "-tuln"]) or _run(["netstat", "-tuln"])
    for port in CARIBBEAN_PORTS:
        if str(port) in ss:
            findings.append({"severity": "HIGH", "type": "risky_port", "detail": f"port {port} listening"})
    for p in ["/tmp/.x", "/dev/shm/", "/var/tmp/."]:
        try:
            if Path(p).exists() or (p.endswith("/") and Path(p).is_dir()):
                findings.append({"severity": "MEDIUM", "type": "suspicious_path", "detail": p})
        except Exception: pass
    return {"ok": True, "region": "Caribbean / Trinidad & Tobago", "findings": findings,
            "count": len(findings), "notes": "Regional high-risk ports and drop paths."}
PLAYBOOKS = {
    "REVERSE_SHELL": {"title": "Reverse shell detected", "severity": "CRITICAL", "steps": [
        "1. Note PID, user, full command line", "2. Isolate or quarantine host if needed",
        "3. Capture ps/ss/auth logs", "4. Kill process if confirmed: kill -9 <PID>",
        "5. Hunt persistence: sentinel hunt", "6. Rotate exposed credentials",
        "7. sentinel evidence --hours 24", "8. Notify client / open ticket"]},
    "CANARY_TRIGGERED": {"title": "Canary / decoy touched", "severity": "HIGH", "steps": [
        "1. Identify canary path", "2. Check who accessed it", "3. Review nearby processes",
        "4. Preserve canary for evidence", "5. sentinel timeline && sentinel score",
        "6. Brief client"]},
    "SSH_BRUTE": {"title": "SSH brute-force", "severity": "MEDIUM", "steps": [
        "1. Confirm blocked IPs", "2. Review successful logins", "3. Enforce key-only auth"]},
}
def playbook_get(alert_type):
    key = (alert_type or "").upper().replace(" ", "_")
    if key in PLAYBOOKS: return {"ok": True, **PLAYBOOKS[key], "type": key}
    return {"ok": False, "type": key, "title": "Generic incident",
            "steps": ["1. Capture details", "2. sentinel hunt", "3. sentinel evidence"],
            "available": list(PLAYBOOKS.keys())}
def playbook_list():
    return [{"type": k, "title": v["title"], "severity": v["severity"]} for k, v in PLAYBOOKS.items()]
def evidence_pack(hours=24, out_dir=None):
    data = _data()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work = Path(out_dir) if out_dir else (data / f"evidence_{stamp}")
    work.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("alerts.log", "devices.json", "behavioral_baseline.json", "attacker_timeline.json", "heartbeat.json"):
        src = data / name
        if src.exists():
            shutil.copy2(src, work / name); copied.append(name)
    meta = {"created": datetime.now().isoformat(), "host": socket.gethostname(),
            "hours": hours, "files": copied, "org": "TrinTech Digital Defense"}
    (work / "META.json").write_text(json.dumps(meta, indent=2))
    zpath = work.with_suffix(".zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in work.iterdir():
            if f.is_file(): zf.write(f, f.name)
    return {"ok": True, "folder": str(work), "zip": str(zpath), "files": copied, "recent_alerts": 0}
QUEUE_FILE = "offline_queue.jsonl"
def offline_enqueue(alert_type, details, config=None):
    path = _data() / QUEUE_FILE
    entry = {"queued_at": datetime.now().isoformat(), "type": alert_type,
             "details": details if isinstance(details, dict) else {"raw": str(details)[:500]}}
    lines = path.read_text().splitlines() if path.exists() else []
    lines.append(json.dumps(entry))
    path.write_text("\n".join(lines[-500:]) + "\n")
    return {"ok": True, "queued": len(lines)}
def offline_status():
    path = _data() / QUEUE_FILE
    if not path.exists(): return {"ok": True, "count": 0, "items": []}
    items = []
    for line in path.read_text().splitlines()[-20:]:
        try: items.append(json.loads(line))
        except Exception: pass
    total = sum(1 for x in path.read_text().splitlines() if x.strip())
    return {"ok": True, "count": total, "items": items}
def offline_flush(send_fn=None):
    path = _data() / QUEUE_FILE
    if not path.exists(): return {"ok": True, "flushed": 0}
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    flushed = 0
    for line in lines:
        try:
            row = json.loads(line)
            if send_fn: send_fn(row.get("type"), row.get("details"))
            flushed += 1
        except Exception: pass
    path.write_text("")
    return {"ok": True, "flushed": flushed, "errors": 0}
def phase4_self_check(config=None):
    c = ensure_phase4_defaults(config)
    return {"behavioral_enabled": True, "baseline_exists": (_data() / "behavioral_baseline.json").exists(),
            "caribbean_pack": True, "playbooks": len(PLAYBOOKS), "offline_enabled": True,
            "offline_queued": offline_status().get("count", 0), "evidence_ready": True}
