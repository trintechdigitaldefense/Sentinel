import logging
#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 04 — Client-facing read-only web portal slice."""
from __future__ import annotations
import json
import os
import secrets
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    return {}

def ensure_portal_token() -> str:
    c = _cfg()
    portal = c.setdefault("portal", {})
    if not portal.get("token"):
        portal["token"] = secrets.token_urlsafe(24)
        portal.setdefault("port", 8791)
        portal.setdefault("enabled", True)
        cfg = _home() / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        base = {}
        if cfg.exists():
            try:
                base = json.loads(cfg.read_text())
            except Exception:
                base = {}
        base["portal"] = portal
        cfg.write_text(json.dumps(base, indent=2))
    return portal["token"]

def collect_snapshot() -> dict:
    snap = {
        "generated": datetime.now().isoformat(),
        "host": os.uname().nodename if hasattr(os, "uname") else "host",
        "alerts_30d": [],
        "alert_count": 0,
        "drift": {},
        "devices": 0,
        "deadman": {},
        "techniques": [],
    }
    ap = _data() / "alerts.log"
    if ap.exists():
        try:
            lines = ap.read_text(errors="ignore").splitlines()[-200:]
            for line in lines:
                if line.strip():
                    snap["alerts_30d"].append(line.strip()[:200])
            snap["alert_count"] = len(snap["alerts_30d"])
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    try:
        from modules.drift import trend
        snap["drift"] = trend()
    except Exception as e:
        snap["drift"] = {"error": str(e)}
    try:
        from modules.deadman import check_local, check_fleet
        snap["deadman"] = {"local": check_local(), "fleet": check_fleet()}
    except Exception as e:
        snap["deadman"] = {"error": str(e)}
    try:
        from modules.attack_map import summarize_techniques
        alerts = [{"reason": a, "type": "alert"} for a in snap["alerts_30d"][:50]]
        snap["techniques"] = summarize_techniques(alerts)
    except Exception as e:
        logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    dp = _data() / "devices.json"
    if dp.exists():
        try:
            d = json.loads(dp.read_text())
            snap["devices"] = len(d) if isinstance(d, (list, dict)) else 0
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)
    return snap

def render_html(snap: dict, client_name: str = "Client") -> str:
    drift = snap.get("drift") or {}
    score = drift.get("latest_score")
    verdict = drift.get("verdict") or "No drift data yet"
    techniques = snap.get("techniques") or []
    tech_rows = "".join(
        f"<tr><td>{t.get('id')}</td><td>{t.get('name')}</td></tr>" for t in techniques
    ) or "<tr><td colspan=2>None observed in recent alerts</td></tr>"
    alerts = snap.get("alerts_30d") or []
    alert_lis = "".join(f"<li><code>{a}</code></li>" for a in alerts[-15:]) or "<li>No recent alerts</li>"
    dm = snap.get("deadman") or {}
    local = (dm.get("local") or {})
    fleet = (dm.get("fleet") or {})
    alive_cls = "ok" if local.get("alive") else "warn"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL · {client_name}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;background:#0B1F3A;color:#E8F0FE}}
.wrap{{max-width:900px;margin:0 auto;padding:24px}}
h1{{color:#1A8CFF;margin:0 0 4px}}
.sub{{color:#94A3B8;margin-bottom:24px}}
.card{{background:#132B4A;border-radius:12px;padding:16px 20px;margin-bottom:16px}}
.metric{{font-size:2rem;font-weight:700;color:#22D3EE}}
table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #1E3A5F}}
code{{font-size:12px;color:#CBD5E1}}
.ok{{color:#34D399}}.warn{{color:#FBBF24}}
footer{{color:#64748B;font-size:12px;margin-top:24px}}
</style></head><body><div class="wrap">
<h1>SENTINEL</h1>
<div class="sub">TrinTech Digital Defense · {client_name} · read-only portal<br>
Generated {snap.get('generated','')}</div>
<div class="card"><div class="metric">{score if score is not None else '—'}%</div>
<div>Baseline intact (drift score)</div>
<p>{verdict}</p></div>
<div class="card"><strong>Monitored devices</strong>
<div class="metric" style="font-size:1.5rem">{snap.get('devices',0)}</div>
<p>Alerts (recent log): {snap.get('alert_count',0)}</p>
<p>Sensor: <span class="{alive_cls}">{local.get('status','?')}</span>
 · Fleet offline: {len(fleet.get('offline') or [])}</p></div>
<div class="card"><strong>Threat techniques observed (ATT&CK)</strong>
<table><tr><th>ID</th><th>Name</th></tr>{tech_rows}</table></div>
<div class="card"><strong>Recent alerts</strong><ul>{alert_lis}</ul></div>
<footer>Authorized monitoring only · Token-authenticated · TrinTech Digital Defense</footer>
</div></body></html>"""

class PortalHandler(BaseHTTPRequestHandler):
    token = ""
    client_name = "Client"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        tok = (qs.get("token") or [None])[0] or self.headers.get("X-Sentinel-Token")
        if not self.token or tok != self.token:
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized - provide ?token=")
            return
        if u.path in ("/", "/index.html", "/portal"):
            snap = collect_snapshot()
            body = render_html(snap, self.client_name).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/api/status":
            body = json.dumps(collect_snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

def start_portal(port: int = None, background: bool = False) -> dict:
    token = ensure_portal_token()
    c = _cfg().get("portal") or {}
    port = int(port or c.get("port") or 8791)
    name = c.get("client_name") or "Client"
    PortalHandler.token = token
    PortalHandler.client_name = name
    server = HTTPServer(("0.0.0.0", port), PortalHandler)
    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"[+] Portal on port {port}")
    print(f"[+] URL: {url}")
    if background:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return {"ok": True, "port": port, "url": url, "token": token, "background": True}
    print("[*] Serving forever — Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Portal stopped")
    return {"ok": True, "port": port, "url": url, "token": token}
