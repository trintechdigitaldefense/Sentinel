#!/usr/bin/env python3
"""Sentinel Phase 7 — multi-host central, Windows agent, quiet hours, v2.6 release."""
from __future__ import annotations
import json, os, socket
from datetime import datetime, time as dtime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

VERSION = "2.6.0"

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _agents_dir() -> Path:
    d = _data() / "agents"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _save_cfg(c: dict) -> None:
    p = _home() / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(c, indent=2))

def ensure_quiet_defaults(config=None) -> dict:
    c = config if config is not None else _cfg()
    q = c.setdefault("quiet_hours", {})
    q.setdefault("enabled", False)
    q.setdefault("start", "22:00")
    q.setdefault("end", "07:00")
    q.setdefault("allow_critical", True)
    _save_cfg(c)
    return c

def _parse_hhmm(s: str) -> dtime:
    parts = (s or "00:00").strip().split(":")
    return dtime(int(parts[0]) % 24, int(parts[1]) % 60 if len(parts) > 1 else 0)

def in_quiet_hours(now: Optional[datetime] = None) -> bool:
    c = ensure_quiet_defaults()
    q = c.get("quiet_hours") or {}
    if not q.get("enabled"):
        return False
    now = now or datetime.now()
    start = _parse_hhmm(q.get("start", "22:00"))
    end = _parse_hhmm(q.get("end", "07:00"))
    t = now.time()
    if start <= end:
        return start <= t < end
    return t >= start or t < end

def quiet_should_suppress(alert_type: str) -> dict:
    c = ensure_quiet_defaults()
    q = c.get("quiet_hours") or {}
    if not q.get("enabled") or not in_quiet_hours():
        return {"suppress": False, "reason": "not_quiet"}
    at = (alert_type or "").upper().replace(" ", "_")
    if q.get("allow_critical", True) and any(x in at for x in ("REVERSE_SHELL", "CANARY", "CRITICAL", "SELF_INTEGRITY")):
        return {"suppress": False, "reason": "critical_allowed"}
    return {"suppress": True, "reason": "quiet_hours"}

def quiet_status() -> dict:
    c = ensure_quiet_defaults()
    q = c.get("quiet_hours") or {}
    return {"ok": True, "enabled": q.get("enabled"), "start": q.get("start"), "end": q.get("end"),
            "allow_critical": q.get("allow_critical"), "currently_quiet": in_quiet_hours()}

def quiet_set(enabled: Optional[bool] = None, start: Optional[str] = None, end: Optional[str] = None) -> dict:
    c = ensure_quiet_defaults()
    q = c.setdefault("quiet_hours", {})
    if enabled is not None:
        q["enabled"] = bool(enabled)
    if start:
        q["start"] = start
    if end:
        q["end"] = end
    _save_cfg(c)
    return quiet_status()

def agent_report(payload: dict) -> dict:
    host = (payload.get("host") or payload.get("hostname") or "unknown").replace("/", "_")[:80]
    path = _agents_dir() / f"{host}.json"
    row = {
        "host": host,
        "received_at": datetime.now().isoformat(),
        "ip": payload.get("ip"),
        "version": payload.get("version", VERSION),
        "status": payload.get("status", "ok"),
        "heartbeat": payload.get("heartbeat"),
        "alerts_24h": payload.get("alerts_24h"),
        "scan_subnets": payload.get("scan_subnets"),
        "os": payload.get("os", "linux"),
    }
    path.write_text(json.dumps(row, indent=2))
    return {"ok": True, "file": str(path), "host": host}

def agents_list() -> dict:
    rows = []
    now = datetime.now()
    for p in sorted(_agents_dir().glob("*.json")):
        try:
            d = json.loads(p.read_text())
            age = None
            try:
                age = int((now - datetime.fromisoformat(d["received_at"])).total_seconds())
            except Exception:
                pass
            d["age_seconds"] = age
            d["alive"] = age is not None and age < 600
            rows.append(d)
        except Exception:
            continue
    return {"ok": True, "count": len(rows), "agents": rows}

def central_status_html() -> str:
    data = agents_list()
    rows = ""
    for a in data.get("agents") or []:
        badge = "ALIVE" if a.get("alive") else "STALE"
        color = "#0F766E" if a.get("alive") else "#C2410C"
        rows += f"<tr><td>{a.get('host')}</td><td>{a.get('ip') or '-'}</td><td>{a.get('os')}</td>"
        rows += f"<td><span style='background:{color};padding:2px 8px;border-radius:999px;color:#fff'>{badge}</span></td>"
        rows += f"<td>{a.get('age_seconds')}s</td><td>{a.get('alerts_24h')}</td><td>{a.get('version')}</td></tr>"
    if not rows:
        rows = "<tr><td colspan='7'>No agents reported yet</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><meta http-equiv=\"refresh\" content=\"30\"/>
<title>SENTINEL Central</title>
<style>
body{{font-family:system-ui;margin:0;background:#0B1F3A;color:#E2E8F0}}
header{{padding:1rem 1.5rem;background:#071525;border-bottom:3px solid #1A8CFF}}
main{{padding:1.5rem;max-width:1000px;margin:0 auto}}
table{{width:100%;border-collapse:collapse;background:#132337}}
th,td{{text-align:left;padding:.5rem;border-bottom:1px solid #1e3a5f;font-size:.9rem}}
</style></head><body>
<header><h1>SENTINEL Central</h1><div>Multi-host · TrinTech · v{VERSION}</div></header>
<main><p>Agents: <b>{data.get('count', 0)}</b></p>
<table><tr><th>Host</th><th>IP</th><th>OS</th><th>Status</th><th>Age</th><th>Alerts</th><th>Ver</th></tr>
{rows}</table></main></body></html>"""

def central_serve(host: str = "0.0.0.0", port: int = 8790) -> None:
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/agents"):
                body = json.dumps(agents_list()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = central_status_html().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            if self.path.startswith("/api/report"):
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    payload = json.loads(self.rfile.read(n).decode() or "{}")
                except Exception:
                    payload = {}
                res = agent_report(payload)
                body = json.dumps(res).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()
        def log_message(self, *a):
            pass
    httpd = HTTPServer((host, port), H)
    print(f"[+] SENTINEL central http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] central stopped")

def agent_self_report(central_url: Optional[str] = None) -> dict:
    try:
        from modules.phase5 import status_json, heartbeat_status
        st = status_json()
        hb = heartbeat_status()
    except Exception:
        st, hb = {}, {}
    payload = {
        "host": socket.gethostname(),
        "version": VERSION,
        "status": "ok",
        "heartbeat": hb,
        "alerts_24h": st.get("alerts_24h_approx"),
        "scan_subnets": st.get("scan_subnets"),
        "os": "linux",
    }
    agent_report(payload)
    if central_url:
        try:
            import urllib.request
            req = urllib.request.Request(
                central_url.rstrip("/") + "/api/report",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return {"ok": True, "posted": True, "response": resp.read().decode()[:300]}
        except Exception as e:
            return {"ok": False, "posted": False, "error": str(e), "payload": payload}
    return {"ok": True, "posted": False, "payload": payload}

def write_windows_agent() -> dict:
    src = Path(__file__).resolve().parent.parent / "agents" / "sentinel_win_agent.py"
    if not src.exists():
        return {"ok": False, "error": "agents/sentinel_win_agent.py missing from repo"}
    return {"ok": True, "file": str(src), "note": "Limited Windows agent: process count + heartbeat"}

def release_info() -> dict:
    return {
        "ok": True,
        "version": VERSION,
        "tag": f"v{VERSION}",
        "product": "SENTINEL",
        "org": "TrinTech Digital Defense",
        "features": [
            "continuous_hunt", "canaries", "fim", "phase4_5_6",
            "always_on_systemd", "whatsapp_digest", "alert_hygiene",
            "multi_host_central", "windows_agent_limited", "quiet_hours",
        ],
        "git_tag_hint": f"git tag -a v{VERSION} -m 'SENTINEL {VERSION}' && git push origin v{VERSION}",
    }

def phase7_self_check() -> dict:
    ensure_quiet_defaults()
    return {
        "version": VERSION,
        "multi_host_central": True,
        "windows_agent": True,
        "quiet_hours": quiet_status(),
        "agents_registered": agents_list().get("count", 0),
        "release": release_info(),
    }
