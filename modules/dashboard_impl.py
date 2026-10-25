# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL visual dashboard — full visibility + safe control surface."""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
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


def _save_cfg(cfg: dict) -> None:
    p = _home() / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2, default=str))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def ensure_token() -> tuple:
    cfg = _cfg()
    dash = cfg.setdefault("dashboard", {})
    if not dash.get("token"):
        dash["token"] = secrets.token_urlsafe(24)
    dash.setdefault("port", DEFAULT_PORT)
    dash.setdefault("allow_control", True)
    cfg["dashboard"] = dash
    existing = _cfg()
    existing["dashboard"] = dash
    _save_cfg(existing)
    return dash["token"], int(dash.get("port") or DEFAULT_PORT), dash


def _safe(fn, default=None):
    try:
        return fn()
    except Exception as e:
        if default is None:
            return {"error": str(e)}
        if isinstance(default, dict):
            return {**default, "error": str(e)}
        return default


def collect_full() -> dict:
    out = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "product": "SENTINEL",
        "version": "3.13.2",
    }
    try:
        out["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        out["local_ip"] = ""

    out["ops"] = _safe(lambda: __import__("modules.ops_status", fromlist=["collect"]).collect(), {})
    out["siem"] = _safe(lambda: __import__("modules.siem", fromlist=["status"]).status(), {})
    out["critical"] = _safe(lambda: __import__("modules.critical_alerts", fromlist=["status"]).status(), {"open": [], "open_count": 0})

    def _vis():
        from modules.visibility import full_inventory
        inv = full_inventory()
        return {
            "devices": (inv.get("devices") or {}).get("count"),
            "live_arp": (inv.get("devices") or {}).get("live_arp"),
            "processes": (inv.get("processes") or {}).get("total"),
            "fim": inv.get("fim"),
            "persistence": inv.get("persistence"),
            "raw": inv,
        }
    out["visibility"] = _safe(_vis, {})

    mp = _data() / "hunt_metrics.json"
    if mp.exists():
        try:
            out["hunt"] = json.loads(mp.read_text())
        except Exception:
            out["hunt"] = {}
    else:
        out["hunt"] = (out.get("ops") or {}).get("hunt") or {}

    hb = _data() / "heartbeat.json"
    if hb.exists():
        try:
            out["heartbeat"] = json.loads(hb.read_text())
        except Exception:
            out["heartbeat"] = {"present": True}
    else:
        out["heartbeat"] = {"present": False}

    ap = _data() / "alerts.log"
    recent = []
    total = 0
    if ap.exists():
        try:
            lines = ap.read_text(errors="ignore").splitlines()
            total = len(lines)
            for ln in lines[-30:]:
                try:
                    recent.append(json.loads(ln))
                except Exception:
                    pass
        except Exception:
            pass
    out["recent_alerts"] = list(reversed(recent))
    out["alert_total"] = total

    out["firewall"] = _safe(lambda: __import__("modules.firewall", fromlist=["status"]).status(), {})

    try:
        from modules.brute_force import status as bf_status
        out["ssh_blocks"] = bf_status()
    except Exception as e:
        out["ssh_blocks"] = {"error": str(e)}

    gl = _data() / "go_live_report.json"
    if gl.exists():
        try:
            out["go_live"] = json.loads(gl.read_text())
        except Exception as e:
            out["go_live"] = {"error": str(e)}
    else:
        out["go_live"] = {"ok": False, "note": "run: python3 sentinel.py go-live"}

    try:
        from modules.phase5 import service_status
        out["service"] = service_status()
    except Exception as e:
        out["service"] = {"error": str(e)}

    try:
        from modules.cases import list_cases
        open_cases = []
        for st in ("new", "triaging", "investigating", "contained"):
            try:
                open_cases.extend(list_cases(status=st, limit=15))
            except TypeError:
                open_cases.extend(list_cases(limit=15))
                break
        out["cases_open"] = open_cases[:25]
        out["cases_open_count"] = len(open_cases)
    except Exception as e:
        out["cases_open"] = []
        out["cases_open_count"] = 0
        out["cases_error"] = str(e)

    # Blocklist summary
    bl_path = _data() / "iptables_blocklist.json"
    blocked = {}
    if bl_path.exists():
        try:
            blocked = (json.loads(bl_path.read_text()) or {}).get("blocked") or {}
        except Exception:
            pass
    out["blocklist"] = {"count": len(blocked), "ips": list(blocked.keys())[:20]}

    cfg = _cfg()
    quiet = False
    try:
        q = (cfg.get("alerting") or {}).get("quiet_hours") or cfg.get("quiet") or {}
        quiet = bool(q.get("enabled") or cfg.get("quiet_mode"))
    except Exception:
        pass
    out["quiet"] = quiet
    out["config_flags"] = {
        "siem_enabled": bool(((cfg.get("alerting") or {}).get("siem") or {}).get("enabled")),
        "ssh_blocking": bool((cfg.get("ssh_blocking") or {}).get("active", True)),
        "deception": bool((cfg.get("deception") or {}).get("active", True)),
        "dashboard_control": bool((cfg.get("dashboard") or {}).get("allow_control", True)),
        "quiet": quiet,
    }
    try:
        from modules.realtime_threat import snapshot as _rt_snap
        out["realtime"] = _rt_snap(emit_alerts=False)
    except Exception as e:
        out["realtime"] = {"ok": False, "error": str(e), "level": "UNKNOWN", "threats": []}

    out["control"] = bool((cfg.get("dashboard") or {}).get("allow_control", True))

    try:
        from modules.dashboard_enrich import enrich
        enrich(out)
    except Exception:
        pass
    return out


def _engine() -> Path:
    return Path(__file__).resolve().parent.parent / "sentinel.py"


def run_cli(*args: str) -> dict:
    """Run a sentinel CLI subcommand (safe control actions)."""
    eng = _engine()
    if not eng.exists():
        return {"ok": False, "error": "sentinel.py not found"}
    try:
        p = subprocess.run(
            [sys.executable, str(eng), *args],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(eng.parent),
        )
        return {
            "ok": p.returncode == 0,
            "code": p.returncode,
            "stdout": (p.stdout or "")[-2000:],
            "stderr": (p.stderr or "")[-1000:],
            "args": list(args),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "args": list(args)}


def _html(token: str, data: dict) -> str:
    def esc(s):
        return (
            str(s if s is not None else "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    control = bool(data.get("control", True))
    ops = data.get("ops") or {}
    siem = data.get("siem") or {}
    crit = data.get("critical") or {}
    vis = data.get("visibility") or {}
    hunt = data.get("hunt") or {}
    fw = data.get("firewall") or {}
    flags = data.get("config_flags") or {}
    recent = data.get("recent_alerts") or []
    open_crit = crit.get("open") or []
    go_live = data.get("go_live") or {}
    service = data.get("service") or {}
    cases = data.get("cases_open") or []
    blocks = data.get("blocklist") or {}
    sshb = data.get("ssh_blocks") or {}
    hb = data.get("heartbeat") or {}

    crit_rows = ""
    for it in open_crit[:20]:
        aid = esc(it.get("id"))
        ack_cell = (
            f"<button class='btn btn-sm' onclick=\"ackCritical('{aid}')\">ACK</button>"
            if control
            else "<span class='muted'>view-only</span>"
        )
        crit_rows += (
            f"<tr><td><code>{aid}</code></td>"
            f"<td class='crit'>{esc(it.get('type'))}</td>"
            f"<td>{esc(it.get('count'))}</td>"
            f"<td>{esc(str(it.get('last_seen') or '')[:19])}</td>"
            f"<td>{ack_cell}</td></tr>"
        )
    if not crit_rows:
        crit_rows = "<tr><td colspan='5' class='muted'>No open critical alerts</td></tr>"

    alert_rows = ""
    for a in recent[:15]:
        alert_rows += (
            f"<tr><td>{esc(str(a.get('timestamp') or a.get('ts') or '')[:19])}</td>"
            f"<td>{esc(a.get('type') or a.get('title'))}</td>"
            f"<td class='mono'>{esc(json.dumps(a.get('details') or a.get('detail') or '')[:100])}</td></tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='3' class='muted'>No alerts yet</td></tr>"

    case_rows = ""
    for c in cases[:12]:
        case_rows += (
            f"<tr><td>{esc(c.get('id') or c.get('case_id'))}</td>"
            f"<td>{esc(c.get('title') or c.get('type'))}</td>"
            f"<td>{esc(c.get('status'))}</td>"
            f"<td>{esc(str(c.get('updated_at') or c.get('created_at') or '')[:19])}</td></tr>"
        )
    if not case_rows:
        case_rows = "<tr><td colspan='4' class='muted'>No open cases</td></tr>"

    block_ips = ", ".join(esc(ip) for ip in (blocks.get("ips") or [])[:12]) or "—"
    siem_badge = "on" if siem.get("enabled") or flags.get("siem_enabled") else "off"
    fw_backend = fw.get("backend") or "none"
    gl_ok = go_live.get("ok")
    gl_label = "READY" if gl_ok else ("PARTIAL" if go_live.get("steps") else "NOT RUN")
    gl_badge = "on" if gl_ok else "warn"
    gl_summary = ", ".join(
        f"{s.get('step')}={'ok' if s.get('ok') else 'fail'}"
        for s in (go_live.get("steps") or [])[:8]
    ) or go_live.get("note") or "—"

    svc_txt = esc(service.get("status") or service.get("state") or service)
    quiet_on = bool(data.get("quiet") or flags.get("quiet"))

    rt = data.get("realtime") or {}
    rt_level = str(rt.get("level") or "UNKNOWN")
    rt_badge = {"CRITICAL": "bad", "HIGH": "warn", "ELEVATED": "warn", "WATCH": "off", "CLEAR": "on"}.get(rt_level, "off")
    rt_rows = ""
    for t in (rt.get("threats") or [])[:15]:
        det = t.get("cmd") or t.get("detail") or t.get("id") or t.get("port") or ""
        rt_rows += (
            f"<tr><td>{esc(t.get('severity'))}</td>"
            f"<td class='crit'>{esc(t.get('type'))}</td>"
            f"<td class='mono'>{esc(str(det)[:120])}</td></tr>"
        )
    if not rt_rows:
        for t in (rt.get("recent_high_alerts") or [])[:8]:
            rt_rows += (
                f"<tr><td>{esc(t.get('severity'))}</td>"
                f"<td>{esc(t.get('type'))}</td>"
                f"<td class='mono'>{esc(str(t.get('detail') or t.get('ts') or '')[:120])}</td></tr>"
            )
    if not rt_rows:
        rt_rows = "<tr><td colspan='3' class='muted'>No active threats detected</td></tr>"

    control_panel = ""
    if control:
        control_panel = f"""
  <div class="section card" id="control">
    <h2>Quick actions (control mode)</h2>
    <div class="actions">
      <button class="btn" onclick="runAction('refresh')">Refresh status</button>
      <button class="btn secondary" onclick="runAction('doctor')">Run doctor</button>
      <button class="btn secondary" onclick="runAction('ops')">Refresh ops</button>
      <button class="btn secondary" onclick="runAction('go-live-status')">Show go-live report</button>
      <button class="btn secondary" onclick="runAction('quiet-on')">Quiet ON</button>
      <button class="btn secondary" onclick="runAction('quiet-off')">Quiet OFF</button>
      <button class="btn secondary" onclick="runAction('field-soak')">Field-soak (no confirm)</button>
      <button class="btn secondary" onclick="runAction('visibility')">Visibility scan</button>
      <button class="btn secondary" onclick="runAction('service-status')">Service status</button>
      <button class="btn btn-sm" onclick="ackAllCritical()">ACK all critical</button>
    </div>
    <pre id="action-out" class="mono outbox">Ready.</pre>
    <p class="muted">Destructive or long-running actions (full hunt, firewall apply, deception redeploy) stay on CLI for safety.</p>
  </div>
"""
    else:
        control_panel = """
  <div class="section card"><h2>Control</h2>
    <p class="muted">View-only mode (<code>dashboard.allow_control: false</code>). Critical ACK and actions disabled.</p>
  </div>
"""

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
  display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap;
  padding:1rem 1.5rem; border-bottom:1px solid var(--border);
  background:rgba(18,26,43,.9); position:sticky; top:0; z-index:10;
}}
header h1 {{ margin:0; font-size:1.15rem; letter-spacing:.04em; }}
header .meta {{ color:var(--muted); font-size:.85rem; }}
nav a {{ color:#93c5fd; margin-right:.75rem; text-decoration:none; font-size:.8rem; }}
.wrap {{ padding:1.25rem; max-width:1200px; margin:0 auto; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:.85rem; }}
.card {{
  background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:1rem 1.1rem;
  box-shadow:0 8px 24px rgba(0,0,0,.25);
}}
.card h2 {{ margin:0 0 .55rem; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
.metric {{ font-size:1.45rem; font-weight:700; }}
.muted {{ color:var(--muted); }}
.badge {{ display:inline-block; padding:.15rem .55rem; border-radius:999px; font-size:.75rem; font-weight:600; }}
.badge.on {{ background:rgba(34,197,94,.15); color:var(--good); }}
.badge.off {{ background:rgba(148,163,184,.15); color:var(--muted); }}
.badge.warn {{ background:rgba(245,158,11,.15); color:var(--warn); }}
.badge.bad {{ background:rgba(239,68,68,.2); color:var(--bad); }}
.crit {{ color:var(--crit); font-weight:600; }}
table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
th, td {{ text-align:left; padding:.4rem .35rem; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.78rem; color:#c7d2fe; }}
.actions {{ display:flex; flex-wrap:wrap; gap:.45rem; margin-top:.5rem; }}
.btn {{
  background:#1d4ed8; color:white; border:none; border-radius:8px; padding:.4rem .75rem;
  font-size:.8rem; cursor:pointer; text-decoration:none; display:inline-block;
}}
.btn.secondary {{ background:#334155; }}
.btn-sm {{ padding:.25rem .55rem; font-size:.75rem; background:#be123c; }}
.btn:hover {{ filter:brightness(1.08); }}
.section {{ margin-top:1.1rem; }}
.outbox {{
  margin-top:.75rem; padding:.75rem; background:#0a0f1a; border-radius:8px;
  max-height:220px; overflow:auto; white-space:pre-wrap; border:1px solid var(--border);
}}
footer {{ color:var(--muted); font-size:.75rem; padding:1.5rem; text-align:center; }}
.switch {{ position:relative; display:inline-block; width:42px; height:22px; vertical-align:middle; margin-left:.5rem; }}
.switch input {{ opacity:0; width:0; height:0; }}
.slider {{ position:absolute; cursor:pointer; inset:0; background:#334155; border-radius:22px; transition:.2s; }}
.slider:before {{ position:absolute; content:""; height:16px; width:16px; left:3px; bottom:3px; background:white; border-radius:50%; transition:.2s; }}
.switch input:checked + .slider {{ background:#1d4ed8; }}
.switch input:checked + .slider:before {{ transform:translateX(20px); }}
#rt-live {{ font-weight:600; }}
#rt-live.pulse {{ animation: pulse 1.2s infinite; }}
@keyframes pulse {{ 0%{{opacity:1}} 50%{{opacity:.45}} 100%{{opacity:1}} }}

</style>
</head>
<body>
<header>
  <div>
    <h1>SENTINEL · Full dashboard</h1>
    <div class="meta">{esc(data.get('host'))} · {esc(data.get('local_ip'))} · v{esc(data.get('version'))} · {esc(str(data.get('ts') or '')[:19])}Z</div>
    <nav>
      <a href="#overview">Overview</a>
      <a href="#critical">Critical</a>
      <a href="#alerts">Alerts</a>
      <a href="#visibility">Visibility</a>
      <a href="#defense">Defense</a>
      <a href="#cases">Cases</a>
      <a href="#control">Control</a>
    </nav>
  </div>
  <div class="meta">
    SIEM <span class="badge {siem_badge}">{siem_badge.upper()}</span>
    · FW <span class="badge {'on' if fw_backend!='none' else 'off'}">{esc(fw_backend)}</span>
    · Quiet <span class="badge {'warn' if quiet_on else 'off'}">{'ON' if quiet_on else 'OFF'}</span>
    · <span id="ctrl-label" data-control="{str(control).lower()}">{'CONTROL' if control else 'VIEW-ONLY'}</span>
    <label class="switch" title="Enable or disable dashboard controls">
      <input type="checkbox" id="ctrl-toggle" {'checked' if control else ''} onchange="toggleControl(this.checked)"/>
      <span class="slider"></span>
    </label>
    <span class="muted" style="margin-left:.35rem;font-size:.75rem">{'Controls on' if control else 'Controls off'}</span>
  </div>
</header>
<div class="wrap">
  <div class="card section" id="realtime" style="margin-top:0">
    <h2>Real-time threat detection <span id="rt-live" class="badge on">LIVE</span></h2>
    <p>
      <span class="badge {rt_badge}">{esc(rt_level)}</span>
      · score <b>{esc(rt.get("score", 0))}</b>
      · threats <b>{esc(rt.get("threat_count", 0))}</b>
      · <span class="muted">{esc(str(rt.get("ts") or "")[:19])}</span>
    </p>
    <table>
      <tr><th>Severity</th><th>Type</th><th>Detail</th></tr>
      {rt_rows}
    </table>
    <div class="actions">
      <button class="btn secondary" onclick="runAction('realtime-scan')">Re-scan now</button>
      <a class="btn secondary" href="/api/realtime?token={esc(token)}">Realtime JSON</a>
    </div>
  </div>
  <div class="grid" id="overview">
    <div class="card"><h2>Hunt cycles</h2><div class="metric">{esc(hunt.get('cycles', 0))}</div>
      <div class="muted">last {esc(hunt.get('last_cycle_sec', '—'))}s · ok={esc(hunt.get('last_ok'))}</div></div>
    <div class="card"><h2>Critical open</h2><div class="metric" style="color:var(--crit)">{esc(crit.get('open_count', 0))}</div>
      <div class="muted">persist until ACK</div></div>
    <div class="card"><h2>Alerts total</h2><div class="metric">{esc(data.get('alert_total', 0))}</div>
      <div class="muted">offline q {esc(ops.get('offline_queue', 0))}</div></div>
    <div class="card"><h2>Devices</h2><div class="metric">{esc(vis.get('devices', 0))}</div>
      <div class="muted">ARP live {esc(vis.get('live_arp', 0))}</div></div>
    <div class="card"><h2>Processes</h2><div class="metric">{esc(vis.get('processes', 0))}</div>
      <div class="muted">FIM {(vis.get('fim') or {}).get('files', '—')}</div></div>
    <div class="card"><h2>SIEM ship</h2><div class="metric">{esc(siem.get('ship_file_lines', 0))}</div>
      <div class="muted">syslog={esc(siem.get('syslog'))} hec={esc(siem.get('splunk_hec'))}</div></div>
    <div class="card"><h2>SSH blocks</h2><div class="metric">{esc(sshb.get('active_blocks', blocks.get('count', 0)))}</div>
      <div class="muted">blocklist {esc(blocks.get('count', 0))}</div></div>
    <div class="card"><h2>Cases open</h2><div class="metric">{esc(data.get('cases_open_count', 0))}</div>
      <div class="muted">service: {svc_txt[:40]}</div></div>
  </div>

  <div class="section card" id="critical">
    <h2>Open critical alerts</h2>
    <table>
      <tr><th>ID</th><th>Type</th><th>Count</th><th>Last seen</th><th>Action</th></tr>
      {crit_rows}
    </table>
  </div>

  <div class="section card" id="alerts">
    <h2>Recent alerts</h2>
    <table>
      <tr><th>Time</th><th>Type</th><th>Detail</th></tr>
      {alert_rows}
    </table>
  </div>

  <div class="section card" id="visibility">
    <h2>Visibility &amp; host</h2>
    <p class="muted">Heartbeat: <span class="mono">{esc(hb.get('ts') or hb.get('present') or 'none')}</span></p>
    <p class="muted">Go-live: <span class="badge {gl_badge}">{gl_label}</span> <span class="mono">{esc(gl_summary)}</span></p>
    <p class="muted">Blocked IPs: <span class="mono">{block_ips}</span></p>
  </div>

  <div class="section card" id="defense">
    <h2>Defense plane</h2>
    <p class="muted">Firewall backend=<span class="mono">{esc(fw_backend)}</span>
       lockout=<span class="mono">{esc(fw.get('lockout_guard'))}</span>
       deception=<span class="mono">{esc(flags.get('deception'))}</span>
       ssh_blocking=<span class="mono">{esc(flags.get('ssh_blocking'))}</span></p>
    <p class="muted">SIEM path: <span class="mono">{esc(siem.get('ship_file'))}</span></p>
  </div>

  <div class="section card" id="cases">
    <h2>Open cases</h2>
    <table>
      <tr><th>ID</th><th>Title</th><th>Status</th><th>Updated</th></tr>
      {case_rows}
    </table>
  </div>

  {control_panel}

  <div class="section card">
    <h2>API</h2>
    <div class="actions">
      <a class="btn secondary" href="?token={esc(token)}">Reload UI</a>
      <a class="btn secondary" href="/api/status?token={esc(token)}">Full JSON</a>
      <a class="btn secondary" href="/api/critical?token={esc(token)}">Critical JSON</a>
      <a class="btn secondary" href="/api/go-live?token={esc(token)}">Go-live JSON</a>
    </div>
  </div>
</div>
<footer>TrinTech Digital Defense · Authorized defensive use only · Token required</footer>
<script>
const TOKEN = "{esc(token)}";
async function ackCritical(id) {{
  if (!confirm("ACK critical " + id + "?")) return;
  const r = await fetch("/api/critical/ack?token=" + encodeURIComponent(TOKEN), {{
    method: "POST", headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{id}})
  }});
  const j = await r.json();
  if (!r.ok || !j.ok) {{ alert("Failed: " + (j.error || r.status)); return; }}
  location.reload();
}}
async function ackAllCritical() {{
  if (!confirm("ACK ALL open criticals?")) return;
  const r = await fetch("/api/critical/ack-all?token=" + encodeURIComponent(TOKEN), {{
    method: "POST", headers: {{"Content-Type": "application/json"}}, body: "{{}}"
  }});
  const j = await r.json();
  if (!r.ok || !j.ok) {{ alert("Failed: " + (j.error || r.status)); return; }}
  location.reload();
}}
async function runAction(name) {{
  const out = document.getElementById("action-out");
  if (out) out.textContent = "Running " + name + "...";
  if (name === "refresh") {{ location.reload(); return; }}
  const r = await fetch("/api/action?token=" + encodeURIComponent(TOKEN), {{
    method: "POST", headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{action: name}})
  }});
  const j = await r.json();
  if (out) out.textContent = JSON.stringify(j, null, 2);
}}
async function toggleControl(want) {{
  if (typeof want !== "boolean") {{
    const el = document.getElementById("ctrl-label");
    const cur = el && el.getAttribute("data-control") === "true";
    want = !cur;
  }}
  try {{
    const r = await fetch("/api/control-mode?token=" + encodeURIComponent(TOKEN), {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{allow_control: want}})
    }});
    const j = await r.json();
    if (!r.ok || !j.ok) {{
      alert("Toggle failed: " + (j.error || r.status));
      const box = document.getElementById("ctrl-toggle");
      if (box) box.checked = !want;
      return;
    }}
    location.reload();
  }} catch (e) {{
    alert("Toggle error: " + e);
    const box = document.getElementById("ctrl-toggle");
    if (box) box.checked = !want;
  }}
}}

function renderThreats(rt) {{
  const badge = document.querySelector("#realtime .badge");
  const live = document.getElementById("rt-live");
  if (live) {{ live.textContent = "LIVE"; live.className = "badge on pulse"; }}
  if (!rt) return;
  const level = rt.level || "UNKNOWN";
  const map = {{CRITICAL:"bad", HIGH:"warn", ELEVATED:"warn", WATCH:"off", CLEAR:"on"}};
  // first badge after h2 is level
  const badges = document.querySelectorAll("#realtime .badge");
  if (badges.length >= 2) {{
    badges[1].textContent = level;
    badges[1].className = "badge " + (map[level] || "off");
  }}
  const tbodyHint = document.querySelector("#realtime table");
  if (!tbodyHint) return;
  let rows = "";
  const threats = rt.threats || [];
  if (threats.length) {{
    for (const t of threats.slice(0, 15)) {{
      const det = t.cmd || t.detail || t.id || t.port || "";
      rows += "<tr><td>" + (t.severity||"") + "</td><td class=\"crit\">" + (t.type||"") +
              "</td><td class=\"mono\">" + String(det).slice(0,120) + "</td></tr>";
    }}
  }} else {{
    rows = "<tr><td colspan=\"3\" class=\"muted\">No active threats detected</td></tr>";
  }}
  tbodyHint.innerHTML = "<tr><th>Severity</th><th>Type</th><th>Detail</th></tr>" + rows;
  const scoreEl = document.querySelector("#realtime p b");
  // update score/count text roughly via full p
}}

async function pollRealtime() {{
  try {{
    const r = await fetch("/api/realtime?token=" + encodeURIComponent(TOKEN) + "&scan=1");
    if (!r.ok) return;
    const j = await r.json();
    renderThreats(j);
  }} catch (e) {{}}
}}

const RT_LEVEL = "{esc(rt_level)}";
const POLL_MS = (RT_LEVEL === "CRITICAL" || RT_LEVEL === "HIGH") ? 8000 : 12000;
setInterval(pollRealtime, POLL_MS);
// soft full reload less often to refresh other panels
const REFRESH_MS = (RT_LEVEL === "CRITICAL" || RT_LEVEL === "HIGH") ? 60000 : 120000;
setTimeout(function(){{ location.href = location.pathname + location.search; }}, REFRESH_MS);
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

    def _read_json_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        raw = self.rfile.read(n) if n > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def do_GET(self):
        if not self._auth_ok():
            self._send(401, b"Unauthorized - add ?token=...")
            return
        path = urlparse(self.path).path
        data = collect_full()
        data["control"] = bool(self.allow_control)
        if path in ("/api/critical", "/api/critical/"):
            self._send(200, json.dumps(data.get("critical") or {}, indent=2, default=str).encode(), "application/json")
            return
        if path in ("/api/go-live", "/api/golive"):
            self._send(200, json.dumps(data.get("go_live") or {}, indent=2, default=str).encode(), "application/json")
            return
        if path in ("/api/ops",):
            self._send(200, json.dumps(data.get("ops") or {}, indent=2, default=str).encode(), "application/json")
            return
        if path in ("/api/realtime", "/api/threats"):
            q = parse_qs(urlparse(self.path).query)
            if (q.get("scan") or ["0"])[0] in ("1", "true", "yes"):
                try:
                    from modules.realtime_threat import snapshot
                    data["realtime"] = snapshot(emit_alerts=False)
                except Exception as e:
                    data["realtime"] = {"ok": False, "error": str(e)}
            self._send(200, json.dumps(data.get("realtime") or {}, indent=2, default=str).encode(), "application/json")
            return
        if path in ("/api/visibility",):
            self._send(200, json.dumps(data.get("visibility") or {}, indent=2, default=str).encode(), "application/json")
            return
        if path.startswith("/api/"):
            self._send(200, json.dumps(data, indent=2, default=str).encode(), "application/json")
            return
        self._send(200, _html(self.token, data).encode("utf-8"))

    def do_POST(self):
        if not self._auth_ok():
            self._send(401, b'{"ok":false,"error":"unauthorized"}', "application/json")
            return
        path = urlparse(self.path).path
        body_in = self._read_json_body()

        # Control-mode toggle — allowed with token even in view-only (re-enable controls)
        if "control-mode" in path or path.rstrip("/").endswith("control-mode"):
            want = body_in.get("allow_control")
            if want is None:
                want = not self.allow_control
            want = bool(want)
            cfg = _cfg()
            dash = cfg.setdefault("dashboard", {})
            dash["allow_control"] = want
            cfg["dashboard"] = dash
            _save_cfg(cfg)
            self.allow_control = want
            _Handler.allow_control = want
            self._send(200, json.dumps({"ok": True, "allow_control": want}).encode(), "application/json")
            return

        if not self.allow_control:
            self._send(403, b'{"ok":false,"error":"view-only mode"}', "application/json")
            return

        # Critical ACK
        if "critical" in path and "ack" in path:
            try:
                from modules.critical_alerts import ack, ack_all
                if path.rstrip("/").endswith("ack-all"):
                    result = ack_all(actor="dashboard")
                else:
                    aid = str(body_in.get("id") or body_in.get("alert_id") or "")
                    if not aid:
                        self._send(400, b'{"ok":false,"error":"id required"}', "application/json")
                        return
                    result = ack(aid, actor="dashboard")
                self._send(200 if result.get("ok") else 400, json.dumps(result, default=str).encode(), "application/json")
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
            return

        # Safe actions
        if path.rstrip("/").endswith("/api/action") or path.endswith("action"):
            action = str(body_in.get("action") or "").strip().lower()
            allowed = {
                "doctor": ("doctor",),
                "ops": ("ops",),
                "go-live-status": ("ops",),  # report is file-backed; ops is safe
                "quiet-on": ("quiet", "on"),
                "quiet-off": ("quiet", "off"),
                "field-soak": ("field-soak",),
                "visibility": ("visibility",),
                "service-status": ("service-status",),
                "realtime-scan": ("realtime",),
            }
            if action == "realtime-scan":
                try:
                    from modules.realtime_threat import snapshot
                    result = snapshot(emit_alerts=False)
                    self._send(200, json.dumps({"ok": True, "realtime": result}, default=str).encode(), "application/json")
                except Exception as e:
                    self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
                return
            if action not in allowed:
                self._send(
                    400,
                    json.dumps({"ok": False, "error": f"action not allowed: {action}", "allowed": list(allowed)}).encode(),
                    "application/json",
                )
                return
            # quiet may need config-only fallback
            if action in ("quiet-on", "quiet-off"):
                cfg = _cfg()
                cfg["quiet_mode"] = action == "quiet-on"
                qh = (cfg.get("alerting") or {}).setdefault("quiet_hours", {})
                qh["enabled"] = action == "quiet-on"
                cfg.setdefault("alerting", {})["quiet_hours"] = qh
                _save_cfg(cfg)
                # still try CLI
                result = run_cli(*allowed[action])
                result["quiet_mode"] = cfg["quiet_mode"]
                self._send(200, json.dumps(result, default=str).encode(), "application/json")
                return
            result = run_cli(*allowed[action])
            self._send(200, json.dumps(result, default=str).encode(), "application/json")
            return

        self._send(404, b'{"ok":false,"error":"unknown endpoint"}', "application/json")


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
    print("[*] Full surface: critical, alerts, visibility, defense, cases, actions")
    print("[*] Serving forever - Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped")
    finally:
        server.server_close()
