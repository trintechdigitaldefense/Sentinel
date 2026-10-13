#!/usr/bin/env python3
"""SENTINEL Client Dashboard — visibility + control with login + optional TLS."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_SESSIONS: dict = {}
SESSION_TTL = 8 * 3600


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


def _hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000).hex()


def ensure_token() -> tuple:
    c = _cfg()
    dash = c.setdefault("dashboard", {})
    if not dash.get("token"):
        dash["token"] = secrets.token_urlsafe(24)
    dash.setdefault("port", 8792)
    dash.setdefault("bind", "127.0.0.1")
    dash.setdefault("client_name", (c.get("portal") or {}).get("client_name") or "Client")
    dash.setdefault("enabled", True)
    dash.setdefault("allow_control", True)
    dash.setdefault("require_login", bool(dash.get("password") or dash.get("password_hash")))
    dash.setdefault("tls_cert", "")
    dash.setdefault("tls_key", "")
    if not dash.get("password_hash"):
        if not dash.get("password"):
            dash["password"] = secrets.token_urlsafe(10)
        salt = secrets.token_hex(8)
        dash["password_salt"] = salt
        dash["password_hash"] = _hash_pw(dash["password"], salt)
        dash["require_login"] = True
    _save_cfg({**c, "dashboard": dash})
    return dash["token"], int(dash.get("port") or 8792), dash


def _check_password(password: str, dash: dict) -> bool:
    if not password:
        return False
    salt = dash.get("password_salt") or ""
    expected = dash.get("password_hash") or ""
    if expected and salt:
        got = _hash_pw(password, salt)
        return hmac.compare_digest(got, expected)
    plain = dash.get("password") or ""
    return bool(plain) and hmac.compare_digest(password, plain)


def _new_session() -> str:
    sid = secrets.token_urlsafe(32)
    _SESSIONS[sid] = time.time() + SESSION_TTL
    now = time.time()
    for k, exp in list(_SESSIONS.items()):
        if exp < now:
            _SESSIONS.pop(k, None)
    return sid


def _session_ok(sid) -> bool:
    if not sid:
        return False
    exp = _SESSIONS.get(sid)
    if not exp:
        return False
    if exp < time.time():
        _SESSIONS.pop(sid, None)
        return False
    return True


def collect_full() -> dict:
    out = {
        "generated": datetime.now().isoformat(),
        "version": "2.9.9",
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
        "canaries_alive": 0,
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
    tracker = _data() / "deception_artifacts" / "config.json"
    if tracker.exists():
        try:
            data = json.loads(tracker.read_text())
            if isinstance(data, dict):
                alive = sum(1 for path in data if Path(path).exists())
                total = len(data)
                out["canaries"] = {"alive": alive, "total": total}
                out["canaries_alive"] = alive
        except Exception:
            out["canaries"] = {"alive": 0, "total": 0}
    else:
        out["canaries"] = {"alive": 0, "total": 0}

    # Drift score (latest)
    try:
        hist = (out.get("drift") or {}).get("history") or []
        if hist:
            out["drift_score"] = hist[-1].get("score")
        elif (out.get("drift") or {}).get("latest_score") is not None:
            out["drift_score"] = out["drift"]["latest_score"]
    except Exception:
        pass

    # Heartbeat age
    try:
        from datetime import datetime as _dt
        hb_path = _data() / "heartbeat.json"
        if hb_path.exists():
            hb = json.loads(hb_path.read_text())
            out["heartbeat"] = hb
            ts = hb.get("ts") or hb.get("timestamp")
            if ts:
                age = int((_dt.now() - _dt.fromisoformat(ts)).total_seconds())
                out["heartbeat_age_seconds"] = max(0, age)
    except Exception:
        pass

    # Quiet hours
    try:
        cfg = _cfg()
        q = (cfg.get("alerting") or {}).get("quiet_hours") or cfg.get("quiet_hours") or {}
        out["quiet"] = {"enabled": bool(q.get("enabled"))}
    except Exception:
        out["quiet"] = {"enabled": False}

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
                str(params.get("detection_type") or params.get("type") or "GENERIC"),
                str(params.get("pattern") or ""),
                host=params.get("host"),
                note=str(params.get("note") or "dashboard"),
            )
        if action == "suppress_del":
            from modules.suppressions import remove_rule
            rid = str(params.get("id") or params.get("rule_id") or "")
            return {"ok": remove_rule(rid), "id": rid}
        if action == "tripwire_deploy":
            from modules.ransomware_tripwire import deploy
            return deploy()
        if action == "quiet_on":
            c = _cfg()
            c.setdefault("quiet", {})["enabled"] = True
            c.setdefault("quiet_hours", {})["enabled"] = True
            _save_cfg(c)
            return {"ok": True, "quiet": True}
        if action == "quiet_off":
            c = _cfg()
            c.setdefault("quiet", {})["enabled"] = False
            c.setdefault("quiet_hours", {})["enabled"] = False
            _save_cfg(c)
            return {"ok": True, "quiet": False}
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
        if action == "emit_heartbeat":
            from modules.deadman import emit_heartbeat
            return emit_heartbeat("dashboard")
        if action == "compute_drift":
            from modules.drift import compute_score
            return compute_score([])
        if action == "persistence_baseline":
            from modules.persistence_hunt import create_baseline
            return create_baseline()
        if action == "device_approve":
            from modules.device_radar import approve
            return approve(str(params.get("key") or ""))
        if action in ("detect", "detect_now"):
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
        if action in ("client_report", "generate_report", "pdf_report"):
            from modules.client_report import generate_client_pdf
            r = generate_client_pdf()
            return r
        if action == "deception_redeploy":
            try:
                import subprocess, sys
                root = Path(__file__).resolve().parent.parent
                subprocess.Popen([sys.executable, str(root / "sentinel.py"), "deception"],
                                 cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return {"ok": True, "msg": "deception redeploy started"}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        if action == "service_start":
            try:
                from modules.phase5 import service_install
                return service_install()
            except Exception as e:
                return {"ok": False, "error": str(e)}
        if action == "service_status":
            try:
                from modules.phase5 import service_status
                return service_status()
            except Exception as e:
                return {"ok": False, "error": str(e)}
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
        "<pre id=s></pre><script>fetch('/api/status',{headers:{'X-Sentinel-Token':'" + token + "'}})"
        ".then(r=>r.json()).then(d=>{document.getElementById('s').textContent=JSON.stringify(d,null,2)})</script>"
        "</body></html>"
    )


def login_page(error: str = "") -> str:
    err = f"<p style='color:#f87171'>{error}</p>" if error else ""
    return f"""<!DOCTYPE html>
<html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">
<title>SENTINEL Login</title>
<style>
body{{font-family:system-ui;background:#0B1F3A;color:#E2E8F0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#132337;padding:2rem;border-radius:12px;width:min(360px,92vw);box-shadow:0 8px 32px #0006}}
h1{{margin:0 0 .25rem;font-size:1.4rem}}
.sub{{opacity:.7;margin-bottom:1.25rem;font-size:.9rem}}
label{{display:block;font-size:.8rem;margin:.75rem 0 .25rem;opacity:.85}}
input{{width:100%;padding:.65rem .75rem;border-radius:8px;border:1px solid #334155;background:#0B1220;color:#E2E8F0;box-sizing:border-box}}
button{{margin-top:1.25rem;width:100%;padding:.75rem;border:0;border-radius:8px;background:#1A8CFF;color:#fff;font-weight:700;cursor:pointer}}
button:hover{{filter:brightness(1.08)}}
</style></head><body>
<div class=card>
  <h1>SENTINEL</h1>
  <div class=sub>TrinTech Digital Defense — Client Dashboard</div>
  {err}
  <form method=POST action=/login>
    <label>Password</label>
    <input type=password name=password required autofocus placeholder=\"Dashboard password\">
    <button type=submit>Sign in</button>
  </form>
</div></body></html>"""


class DashHandler(BaseHTTPRequestHandler):
    token = ""
    client_name = "Client"
    dash_cfg = {}

    def log_message(self, *args):
        pass

    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = unquote(v)
        return out

    def _auth_ok(self) -> bool:
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        tok = (qs.get("token") or [None])[0]
        hdr = self.headers.get("X-Sentinel-Token")
        if self.token and (tok == self.token or hdr == self.token):
            return True
        if _session_ok(self._cookies().get("sentinel_session")):
            return True
        if not self.dash_cfg.get("require_login", True):
            if self.token and self._cookies().get("sentinel_token") == self.token:
                return True
        return False

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def _read_form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n).decode(errors="ignore")
        return {k: (v[0] if v else "") for k, v in parse_qs(raw).items()}

    def _send(self, code, body, ctype="application/json", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            self._send(200, login_page().encode(), "text/html; charset=utf-8")
            return
        if u.path == "/logout":
            sid = self._cookies().get("sentinel_session")
            if sid:
                _SESSIONS.pop(sid, None)
            self._send(302, b"", "text/plain", [
                ("Location", "/login"),
                ("Set-Cookie", "sentinel_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"),
            ])
            return
        if not self._auth_ok():
            accept = self.headers.get("Accept") or ""
            if "text/html" in accept or u.path in ("/", "/index.html", "/dashboard"):
                self._send(401, login_page().encode(), "text/html; charset=utf-8")
            else:
                self._send(401, b'{"error":"unauthorized","login":"/login"}')
            return
        if u.path in ("/api/report.pdf", "/api/report"):
            from modules.client_report import generate_client_pdf
            r = generate_client_pdf()
            if not r.get("ok"):
                self._send(500, json.dumps(r).encode())
                return
            data = Path(r["path"]).read_bytes()
            self._send(200, data, "application/pdf", extra_headers=[
                ("Content-Disposition", f'attachment; filename="{Path(r["path"]).name}"'),
            ])
            return
        if u.path == "/api/status":
            self._send(200, json.dumps(collect_full()).encode())
            return
        if u.path in ("/", "/index.html", "/dashboard"):
            self._send(200, html_page(self.token, self.client_name).encode(), "text/html; charset=utf-8")
            return
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            form = self._read_form()
            pw = form.get("password") or ""
            if _check_password(pw, self.dash_cfg):
                sid = _new_session()
                secure = " Secure;" if self.dash_cfg.get("tls_cert") else ""
                self._send(302, b"OK", "text/plain", [
                    ("Location", "/"),
                    ("Set-Cookie", f"sentinel_session={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict;{secure}"),
                ])
            else:
                self._send(401, login_page("Invalid password").encode(), "text/html; charset=utf-8")
            return
        if not self._auth_ok():
            self._send(401, b'{"error":"unauthorized"}')
            return
        if u.path == "/api/action":
            data = self._read_json()
            result = run_action(data.get("action") or "", data)
            self._send(200, json.dumps(result).encode())
            return
        self._send(404, b'{"error":"not found"}')


def start_dashboard(port=None, background=False) -> dict:
    token, default_port, dash = ensure_token()
    port = int(port or default_port)
    bind = str(dash.get("bind") or "127.0.0.1")
    DashHandler.token = token
    DashHandler.client_name = dash.get("client_name") or "Client"
    DashHandler.dash_cfg = dash
    server = ThreadingHTTPServer((bind, port), DashHandler)

    scheme = "http"
    cert = (dash.get("tls_cert") or "").strip()
    key = (dash.get("tls_key") or "").strip()
    if cert and key and Path(cert).exists() and Path(key).exists():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
        print("[+] TLS enabled (%s)" % cert)
    elif cert or key:
        print("[!] tls_cert/tls_key set but files missing — serving plain HTTP")

    host_show = "127.0.0.1" if bind in ("0.0.0.0", "::") else bind
    url = f"{scheme}://{host_show}:{port}/"
    login_url = f"{scheme}://{host_show}:{port}/login"
    print("[+] SENTINEL Dashboard on %s:%d" % (bind, port))
    print("[+] Open: %s" % login_url)
    print("[+] API token URL: %s?token=%s" % (url.rstrip("/"), token))
    if dash.get("password"):
        print("[+] First-run password (change in config): %s" % dash.get("password"))
        print("    stored hashed — clear dashboard.password after you save it")
    print("[+] Control: %s" % ("enabled" if dash.get("allow_control", True) else "disabled"))
    if background:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return {"ok": True, "url": url, "login": login_url, "port": port, "token": token, "scheme": scheme, "background": True}
    print("[*] Serving forever - Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped")
    return {"ok": True, "url": url, "login": login_url, "port": port, "token": token, "scheme": scheme}


if __name__ == "__main__":
    start_dashboard()
