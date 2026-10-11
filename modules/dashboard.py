#!/usr/bin/env python3
"""SENTINEL Client Dashboard - full visibility + control."""
from __future__ import annotations
import json
import os
import secrets
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
        except Exception:
            pass
    return {}


def _save_cfg(c: dict) -> None:
    p = _home() / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(c, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def ensure_token() -> tuple:
    c = _cfg()
    dash = c.setdefault("dashboard", {})
    if not dash.get("token"):
        dash["token"] = secrets.token_urlsafe(24)
    dash.setdefault("port", 8792)
    dash.setdefault("client_name", (c.get("portal") or {}).get("client_name") or "Client")
    dash.setdefault("enabled", True)
    dash.setdefault("allow_control", True)
    _save_cfg({**c, "dashboard": dash})
    return dash["token"], int(dash.get("port") or 8792), dash


def collect_full() -> dict:
    out = {
        "generated": datetime.now().isoformat(),
        "version": "2.9.1",
        "client": ensure_token()[2].get("client_name") or "Client",
        "host": os.uname().nodename if hasattr(os, "uname") else "host",
        "drift": {},
        "deadman": {},
        "alerts": [],
        "alert_count": 0,
        "techniques": [],
        "usb": {},
        "lateral": {},
        "dns": {},
        "persistence": {},
        "honey": {},
        "tripwire": {},
        "radar": {},
        "fleet": {},
        "suppressions": [],
        "external": {},
        "canaries": 0,
        "control_enabled": bool(ensure_token()[2].get("allow_control", True)),
    }
    try:
        from modules.drift import trend
        out["drift"] = trend()
    except Exception as e:
        out["drift"] = {"error": str(e)}
    try:
        from modules.deadman import check_local, check_fleet
        out["deadman"] = {"local": check_local(), "fleet": check_fleet()}
    except Exception as e:
        out["deadman"] = {"error": str(e)}
    ap = _data() / "alerts.log"
    if ap.exists():
        try:
            lines = [l.strip() for l in ap.read_text(errors="ignore").splitlines() if l.strip()]
            out["alerts"] = lines[-40:]
            out["alert_count"] = len(lines)
        except Exception:
            pass
    try:
        from modules.attack_map import summarize_techniques
        out["techniques"] = summarize_techniques(
            [{"reason": a, "type": "alert"} for a in out["alerts"][-30:]]
        )
    except Exception:
        pass
    for label, mod in [
        ("usb", "usb_watch"),
        ("lateral", "lateral"),
        ("dns", "dns_watch"),
        ("persistence", "persistence_hunt"),
        ("honey", "honeyauth"),
        ("tripwire", "ransomware_tripwire"),
        ("radar", "device_radar"),
        ("external", "external_posture"),
    ]:
        try:
            m = __import__("modules." + mod, fromlist=["check"])
            out[label] = m.check()
        except Exception as e:
            out[label] = {"error": str(e)}
    try:
        from modules.fleet_console import collect_local
        out["fleet"] = collect_local()
    except Exception as e:
        out["fleet"] = {"error": str(e)}
    try:
        from modules.suppressions import list_rules
        out["suppressions"] = list_rules()
    except Exception:
        pass
    decoy = _data() / "deception_artifacts"
    if decoy.exists():
        out["canaries"] = sum(1 for p in decoy.rglob("*") if p.is_file())
    return out


def run_action(action: str, params: dict) -> dict:
    _, _, dash = ensure_token()
    if not dash.get("allow_control", True):
        return {"ok": False, "error": "control disabled"}
    action = (action or "").lower().strip()
    try:
        if action == "ack":
            from modules.bot import ack_alert
            return ack_alert(str(params.get("id") or params.get("alert_id") or ""))
        if action == "suppress_add":
            from modules.suppressions import add_suppression
            return add_suppression(
                str(params.get("type") or "*"),
                str(params.get("pattern") or ""),
                note=str(params.get("note") or "dashboard"),
            )
        if action == "suppress_del":
            from modules.suppressions import remove_rule
            rid = str(params.get("id") or "")
            return {"ok": remove_rule(rid), "id": rid}
        if action == "tripwire_deploy":
            from modules.ransomware_tripwire import deploy
            return deploy()
        if action == "persistence_baseline":
            from modules.persistence_hunt import create_baseline
            return create_baseline()
        if action == "device_approve":
            from modules.device_radar import approve
            return approve(str(params.get("key") or ""))
        if action == "emit_heartbeat":
            from modules.deadman import emit_heartbeat
            return emit_heartbeat("dashboard")
        if action == "compute_drift":
            from modules.drift import compute_score
            return compute_score([])
        if action == "quiet_on":
            c = _cfg()
            c.setdefault("quiet_hours", {})["enabled"] = True
            _save_cfg(c)
            return {"ok": True, "quiet_hours": True}
        if action == "quiet_off":
            c = _cfg()
            c.setdefault("quiet_hours", {})["enabled"] = False
            _save_cfg(c)
            return {"ok": True, "quiet_hours": False}
        if action == "usb_on":
            c = _cfg()
            c["usb_watch"] = True
            c.setdefault("detection", {})["usb_watch"] = True
            _save_cfg(c)
            return {"ok": True, "usb_watch": True}
        if action == "usb_off":
            c = _cfg()
            c["usb_watch"] = False
            c.setdefault("detection", {})["usb_watch"] = False
            _save_cfg(c)
            return {"ok": True, "usb_watch": False}
        if action == "detect_now":
            bundle = {}
            for label, mod in [
                ("usb", "usb_watch"),
                ("lateral", "lateral"),
                ("dns", "dns_watch"),
                ("persistence", "persistence_hunt"),
                ("honey", "honeyauth"),
                ("tripwire", "ransomware_tripwire"),
                ("radar", "device_radar"),
            ]:
                try:
                    m = __import__("modules." + mod, fromlist=["check"])
                    bundle[label] = m.check()
                except Exception as e:
                    bundle[label] = {"error": str(e)}
            return {"ok": True, "detect": bundle}
        if action == "refresh":
            return {"ok": True, "status": collect_full()}
        return {"ok": False, "error": "unknown action: " + action}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def html_page(token: str, client: str) -> str:
    tpl = Path(__file__).with_name("dashboard.html")
    if tpl.exists():
        return tpl.read_text().replace("%%TOKEN%%", token).replace("%%CLIENT%%", client)
    return (
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>SENTINEL</title></head>"
        "<body style='font-family:system-ui;background:#0B1220;color:#E8F0FE;padding:24px'>"
        "<h1>SENTINEL Dashboard</h1><p>Client: " + client + "</p>"
        "<pre id=s></pre><script>fetch('/api/status?token=" + token + "')"
        ".then(r=>r.json()).then(d=>{document.getElementById('s').textContent=JSON.stringify(d,null,2)})</script>"
        "</body></html>"
    )


class DashHandler(BaseHTTPRequestHandler):
    token = ""
    client_name = "Client"

    def log_message(self, *args):
        pass

    def _auth_ok(self) -> bool:
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        tok = (qs.get("token") or [None])[0]
        hdr = self.headers.get("X-Sentinel-Token")
        return bool(self.token) and (tok == self.token or hdr == self.token)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if not self._auth_ok():
            self._send(401, b'{"error":"unauthorized"}')
            return
        if u.path in ("/", "/index.html", "/dashboard"):
            body = html_page(self.token, self.client_name).encode()
            self._send(200, body, "text/html; charset=utf-8")
            return
        if u.path == "/api/status":
            self._send(200, json.dumps(collect_full()).encode())
            return
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        u = urlparse(self.path)
        if not self._auth_ok():
            self._send(401, b'{"error":"unauthorized"}')
            return
        if u.path == "/api/action":
            data = self._read_json()
            result = run_action(data.get("action") or "", data)
            self._send(200, json.dumps(result).encode())
            return
        self._send(404, b'{"error":"not found"}')


def start_dashboard(port: int = None, background: bool = False) -> dict:
    token, default_port, dash = ensure_token()
    port = int(port or default_port)
    DashHandler.token = token
    DashHandler.client_name = dash.get("client_name") or "Client"
    server = ThreadingHTTPServer(("0.0.0.0", port), DashHandler)
    url = "http://127.0.0.1:%d/?token=%s" % (port, token)
    print("[+] SENTINEL Dashboard on port %d" % port)
    print("[+] Client URL: %s" % url)
    print("[+] Control: %s" % ("enabled" if dash.get("allow_control", True) else "disabled"))
    if background:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return {"ok": True, "url": url, "port": port, "token": token, "background": True}
    print("[*] Serving forever - Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped")
    return {"ok": True, "url": url, "port": port, "token": token}


if __name__ == "__main__":
    start_dashboard()
