# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL visual dashboard — local HTTP UI with token auth."""
from __future__ import annotations

import json
import os
import secrets
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8792


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


def ensure_token() -> tuple:
    cfg = _cfg()
    dash = cfg.setdefault("dashboard", {})
    if not dash.get("token"):
        dash["token"] = secrets.token_urlsafe(24)
        dash.setdefault("port", DEFAULT_PORT)
        dash.setdefault("allow_control", True)
        cfg["dashboard"] = dash
        p = _home() / "config.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            try:
                existing = json.loads(p.read_text())
            except Exception:
                existing = {}
        else:
            existing = {}
        existing["dashboard"] = dash
        # merge siem enable if requested via env
        p.write_text(json.dumps(existing, indent=2))
        cfg = existing
    port = int(dash.get("port") or DEFAULT_PORT)
    return dash["token"], port, dash


def collect_full() -> dict:
    out = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "product": "SENTINEL",
        "version": "3.10.1",
    }
    try:
        out["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        out["local_ip"] = ""

    # Ops
    try:
        from modules.ops_status import collect
        out["ops"] = collect()
    except Exception as e:
        out["ops"] = {"error": str(e)}

    # SIEM
    try:
        from modules.siem import status as siem_status
        out["siem"] = siem_status()
    except Exception as e:
        out["siem"] = {"error": str(e)}

    # Critical
    try:
        from modules.critical_alerts import status as crit_status
        out["critical"] = crit_status()
    except Exception as e:
        out["critical"] = {"error": str(e)}

    # Visibility
    try:
        from modules.visibility import full_inventory
        inv = full_inventory()
        out["visibility"] = {
            "devices": (inv.get("devices") or {}).get("count"),
            "live_arp": (inv.get("devices") or {}).get("live_arp"),
            "processes": (inv.get("processes") or {}).get("total"),
            "fim": inv.get("fim"),
            "persistence": inv.get("persistence"),
        }
    except Exception as e:
        out["visibility"] = {"error": str(e)}

    # Hunt metrics
    mp = _data() / "hunt_metrics.json"
    if mp.exists():
        try:
            out["hunt"] = json.loads(mp.read_text())
        except Exception:
            out["hunt"] = {}
    else:
        out["hunt"] = {}

    # Recent alerts
    ap = _data() / "alerts.log"
    recent = []
    if ap.exists():
        try:
            for ln in ap.read_text(errors="ignore").splitlines()[-25:]:
                try:
                    recent.append(json.loads(ln))
                except Exception:
                    pass
        except Exception:
            pass
    out["recent_alerts"] = list(reversed(recent))

    # Firewall
    try:
        from modules.firewall import status as fw_status
        out["firewall"] = fw_status()
    except Exception as e:
        out["firewall"] = {"error": str(e)}

    # Config flags (no secrets)
    cfg = _cfg()
    out["config_flags"] = {
        "siem_enabled": bool(((cfg.get("alerting") or {}).get("siem") or {}).get("enabled")),
        "ssh_blocking": bool((cfg.get("ssh_blocking") or {}).get("active", True)),
        "deception": bool((cfg.get("deception") or {}).get("active", True)),
        "dashboard_control": bool((cfg.get("dashboard") or {}).get("allow_control", True)),
    }
    return out


def _html(token: str, data: dict) -> str:
    ops = data.get("ops") or {}
    siem = data.get("siem") or {}
    crit = data.get("critical") or {}
    vis = data.get("visibility") or {}
    hunt = data.get("hunt") or data.get("ops", {}).get("hunt") or {}
    fw = data.get("firewall") or {}
    flags = data.get("config_flags") or {}
    recent = data.get("recent_alerts") or []
    open_crit = crit.get("open") or []

    def esc(s):
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    crit_rows = ""
    for it in open_crit[:15]:
        crit_rows += (
            f"<tr><td><code>{esc(it.get('id'))}</code></td>"
            f"<td class='crit'>{esc(it.get('type'))}</td>"
            f"<td>{esc(it.get('count'))}</td>"
            f"<td>{esc(str(it.get('last_seen') or '')[:19])}</td></tr>"
        )
    if not crit_rows:
        crit_rows = "<tr><td colspan='4' class='muted'>No open critical alerts</td></tr>"

    alert_rows = ""
    for a in recent[:12]:
        alert_rows += (
            f"<tr><td>{esc(str(a.get('timestamp') or a.get('ts') or '')[:19])}</td>"
            f"<td>{esc(a.get('type') or a.get('title'))}</td>"
            f"<td class='mono'>{esc(json.dumps(a.get('details') or a.get('detail') or '')[:80])}</td></tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='3' class='muted'>No alerts yet</td></tr>"

    siem_badge = "on" if siem.get("enabled") or flags.get("siem_enabled") else "off"
    fw_backend = fw.get("backend") or "none"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SENTINEL Dashboard</title>
<style>
:root {{
  --bg:#0b1220; --panel:#121a2b; --border:#1e2a40; --text:#e8eef9; --muted:#8b9bb4;
  --accent:#3b82f6; --good:#22c55e; --warn:#f59e0b; --bad:#ef4444; --crit:#f43f5e;
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  background: radial-gradient(1200px 600px at 10% -10%, #1a2744 0%, var(--bg) 55%);
  color:var(--text); min-height:100vh;
}}
header {{
  display:flex; justify-content:space-between; align-items:center; gap:1rem;
  padding:1rem 1.5rem; border-bottom:1px solid var(--border);
  background:rgba(18,26,43,.85); backdrop-filter:blur(8px); position:sticky; top:0; z-index:10;
}}
header h1 {{ margin:0; font-size:1.15rem; letter-spacing:.04em; }}
header .meta {{ color:var(--muted); font-size:.85rem; }}
.wrap {{ padding:1.25rem; max-width:1200px; margin:0 auto; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; }}
.card {{
  background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:1rem 1.1rem;
  box-shadow:0 8px 24px rgba(0,0,0,.25);
}}
.card h2 {{ margin:0 0 .6rem; font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
.metric {{ font-size:1.6rem; font-weight:700; }}
.muted {{ color:var(--muted); }}
.badge {{ display:inline-block; padding:.15rem .55rem; border-radius:999px; font-size:.75rem; font-weight:600; }}
.badge.on {{ background:rgba(34,197,94,.15); color:var(--good); }}
.badge.off {{ background:rgba(148,163,184,.15); color:var(--muted); }}
.badge.warn {{ background:rgba(245,158,11,.15); color:var(--warn); }}
.badge.bad {{ background:rgba(239,68,68,.15); color:var(--bad); }}
.crit {{ color:var(--crit); font-weight:600; }}
table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
th, td {{ text-align:left; padding:.45rem .35rem; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.78rem; color:#c7d2fe; }}
.actions {{ display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.75rem; }}
.btn {{
  background:#1d4ed8; color:white; border:none; border-radius:8px; padding:.45rem .8rem;
  font-size:.85rem; cursor:pointer; text-decoration:none; display:inline-block;
}}
.btn.secondary {{ background:#334155; }}
.btn:hover {{ filter:brightness(1.08); }}
.section {{ margin-top:1.25rem; }}
footer {{ color:var(--muted); font-size:.75rem; padding:1.5rem; text-align:center; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>SENTINEL · Line of Defense</h1>
    <div class="meta">{esc(data.get('host'))} · {esc(data.get('local_ip'))} · {esc(str(data.get('ts') or '')[:19])}Z</div>
  </div>
  <div class="meta">
    SIEM <span class="badge {siem_badge}">{siem_badge.upper()}</span>
    · FW <span class="badge {'on' if fw_backend!='none' else 'off'}">{esc(fw_backend)}</span>
  </div>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><h2>Hunt cycles</h2><div class="metric">{esc(hunt.get('cycles', 0))}</div>
      <div class="muted">last {esc(hunt.get('last_cycle_sec', '—'))}s · ok={esc(hunt.get('last_ok'))}</div></div>
    <div class="card"><h2>Critical open</h2><div class="metric" style="color:var(--crit)">{esc(crit.get('open_count', 0))}</div>
      <div class="muted">ack: sentinel critical ack &lt;id&gt;</div></div>
    <div class="card"><h2>Devices</h2><div class="metric">{esc(vis.get('devices', 0))}</div>
      <div class="muted">ARP live {esc(vis.get('live_arp', 0))}</div></div>
    <div class="card"><h2>Processes</h2><div class="metric">{esc(vis.get('processes', 0))}</div>
      <div class="muted">FIM {(vis.get('fim') or {}).get('files', '—')}</div></div>
    <div class="card"><h2>SIEM ship</h2><div class="metric">{esc(siem.get('ship_file_lines', 0))}</div>
      <div class="muted">syslog={esc(siem.get('syslog'))} hec={esc(siem.get('splunk_hec'))}</div></div>
    <div class="card"><h2>Alerts total</h2><div class="metric">{esc((ops.get('alerts') or {}).get('total', len(recent)))}</div>
      <div class="muted">offline q {esc(ops.get('offline_queue', 0))}</div></div>
  </div>

  <div class="section card">
    <h2>Open critical alerts</h2>
    <table>
      <tr><th>ID</th><th>Type</th><th>Count</th><th>Last seen</th></tr>
      {crit_rows}
    </table>
  </div>

  <div class="section card">
    <h2>Recent alerts</h2>
    <table>
      <tr><th>Time</th><th>Type</th><th>Detail</th></tr>
      {alert_rows}
    </table>
  </div>

  <div class="section card">
    <h2>SIEM &amp; control plane</h2>
    <p class="muted">Ship file: <span class="mono">{esc(siem.get('ship_file'))}</span></p>
    <p class="muted">Firewall lockout_guard={esc(fw.get('lockout_guard'))} · managed blocks path under ~/.sentinel/data</p>
    <div class="actions">
      <a class="btn" href="?token={esc(token)}&refresh=1">Refresh</a>
      <a class="btn secondary" href="/api/status?token={esc(token)}">JSON API</a>
    </div>
  </div>
</div>
<footer>TrinTech Digital Defense · Authorized defensive use only · Dashboard token required</footer>
<script>
// soft auto-refresh every 30s
setTimeout(function(){{ location.href = location.pathname + location.search; }}, 30000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    token = ""
    allow_control = True

    def log_message(self, fmt, *args):
        pass

    def _auth_ok(self) -> bool:
        q = parse_qs(urlparse(self.path).query)
        t = (q.get("token") or [""])[0]
        if t and t == self.token:
            return True
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer ") and auth[7:] == self.token:
            return True
        return False

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth_ok():
            self._send(401, b"Unauthorized - add ?token=...")
            return
        path = urlparse(self.path).path
        data = collect_full()
        try:
            from modules.dashboard_enrich import enrich
            enrich(data)
        except Exception:
            pass
        if path.startswith("/api/"):
            body = json.dumps(data, indent=2, default=str).encode()
            self._send(200, body, "application/json")
            return
        html = _html(self.token, data)
        self._send(200, html.encode("utf-8"))


def start_dashboard(port: int | None = None, bind: str = "127.0.0.1"):
    token, cfg_port, dash = ensure_token()
    port = int(port or cfg_port or DEFAULT_PORT)
    _Handler.token = token
    _Handler.allow_control = bool(dash.get("allow_control", True))
    server = HTTPServer((bind, port), _Handler)
    url = f"http://{bind}:{port}/?token={token}"
    print(f"[+] SENTINEL Dashboard on port {port}")
    print(f"[+] Client URL: {url}")
    print(f"[+] Control: {'enabled' if _Handler.allow_control else 'view-only'}")
    print("[*] Serving forever - Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped")
    finally:
        server.server_close()
