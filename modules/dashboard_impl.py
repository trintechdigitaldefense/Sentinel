# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL visual dashboard — full visibility + safe control surface."""
from __future__ import annotations
import logging

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
    dash.setdefault("allow_control", False)
    dash.setdefault("role", "viewer")
    dash.setdefault("bind", "127.0.0.1")
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
        "version": "unknown",
    }
    try:
        from sentinel import __version__ as _ver
        out["version"] = str(_ver)
    except Exception:
        pass
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
    def _fleet():
        from modules.network_fleet import fleet_status
        return fleet_status()
    out["fleet"] = _safe(_fleet, {"count": 0, "devices": {}})

    # Canary tracker (accurate counts for dashboard + client PDF)
    try:
        cpath = _data() / "deception_artifacts" / "config.json"
        total = alive = 0
        if cpath.exists():
            import os
            trk = json.loads(cpath.read_text())
            if isinstance(trk, dict):
                total = len(trk)
                for fpath, meta in trk.items():
                    try:
                        if Path(str(fpath)).exists() or Path(str((meta or {}).get("path") or "")).exists():
                            alive += 1
                        elif isinstance(meta, dict) and meta.get("status") != "missing":
                            # path is the key
                            if Path(fpath).exists():
                                alive += 1
                    except Exception:
                        pass
                # if keys are paths
                if alive == 0 and total:
                    for fpath in trk:
                        try:
                            if Path(fpath).is_file():
                                alive += 1
                        except Exception:
                            pass
        out["canaries"] = {"total": total, "alive": alive}
        out["canaries_alive"] = alive
    except Exception as e:
        out["canaries"] = {"total": 0, "alive": 0, "error": str(e)}

    # Heartbeat age for accurate "monitoring paused" verdict
    try:
        hb = out.get("heartbeat") or {}
        if isinstance(hb, dict) and hb.get("ts"):
            from datetime import datetime as _dt
            try:
                when = _dt.fromisoformat(str(hb["ts"]).replace("Z", ""))
                age = (_dt.now() - when).total_seconds()
                hb = dict(hb)
                hb["age_seconds"] = age
                hb["alive"] = age < 300
                out["heartbeat"] = hb
                out["heartbeat_age_seconds"] = age
            except Exception:
                if hb.get("present"):
                    out["heartbeat"] = {**hb, "alive": False}
        elif isinstance(hb, dict) and hb.get("present") is False:
            out["heartbeat"] = {**hb, "alive": False}
    except Exception:
        pass

    # Align alert_total naming for client PDF
    out.setdefault("alerts_24h", out.get("alert_total") or len(out.get("recent_alerts") or []))


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
        "dashboard_control": bool((cfg.get("dashboard") or {}).get("allow_control", False)),
        "quiet": quiet,
    }
    try:
        from modules.realtime_threat import snapshot as _rt_snap
        out["realtime"] = _rt_snap(emit_alerts=False)
    except Exception as e:
        out["realtime"] = {"ok": False, "error": str(e), "level": "UNKNOWN", "threats": []}

    out["control"] = bool((cfg.get("dashboard") or {}).get("allow_control", False))

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



def _logo_asset() -> Path | None:
    """Resolve official report/dashboard logo PNG."""
    base = Path(__file__).resolve().parent / "assets"
    for name in ("trintech_logo_header.png", "trintech_sentinel_logo.png", "trintech_brand.png"):
        cand = base / name
        if cand.is_file() and cand.stat().st_size > 100:
            return cand
    return None

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

    # Plain-language monitoring status for hero banner
    _hb = data.get("heartbeat") or {}
    _alive = bool(_hb.get("alive")) if isinstance(_hb, dict) else False
    _crit_n = int((data.get("critical") or {}).get("open_count") or 0)
    if _crit_n > 0:
        hero_status = "Needs attention"
        hero_class = "hero-bad"
        hero_detail = f"{_crit_n} critical alert(s) still open. TrinTech should review."
    elif _alive:
        hero_status = "Monitoring is active"
        hero_class = "hero-good"
        hero_detail = "Continuous protection is running on this host."
    else:
        hero_status = "Monitoring may be paused"
        hero_class = "hero-warn"
        hero_detail = "Start hunt or service-install so protection stays on 24/7."
    _fleet = data.get("fleet") or {}
    _can = data.get("canaries") or {}


    fleet = data.get("fleet") or {}
    try:
        _prev = {
            k: {
                "ip": v.get("ip"),
                "mac": v.get("mac"),
                "status": v.get("status"),
                "canary": v.get("canary"),
                "ports": (v.get("ports") or [])[:12],
            }
            for k, v in list((fleet.get("devices") or {}).items())[:40]
        }
        fleet_json = json.dumps(_prev, indent=2)
    except Exception:
        fleet_json = "{}"

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
    rt_badge = {"CRITICAL": "bad", "HIGH": "warn", "ELEVATED": "elev", "WATCH": "info", "CLEAR": "on"}.get(rt_level, "off")
    rt_rows = ""
    for t in (rt.get("threats") or [])[:15]:
        det = t.get("cmd") or t.get("detail") or t.get("id") or t.get("port") or ""
        sev = str(t.get("severity") or "MEDIUM").upper()
        rt_rows += (
            f"<tr class='row-{esc(sev)}'><td class='sev-{esc(sev)}'>{esc(sev)}</td>"
            f"<td class='crit'>{esc(t.get('type'))}</td>"
            f"<td class='mono'>{esc(str(det)[:120])}</td></tr>"
        )
    if not rt_rows:
        for t in (rt.get("recent_high_alerts") or [])[:8]:
            sev = str(t.get("severity") or "HIGH").upper()
            rt_rows += (
                f"<tr class='row-{esc(sev)}'><td class='sev-{esc(sev)}'>{esc(sev)}</td>"
                f"<td>{esc(t.get('type'))}</td>"
                f"<td class='mono'>{esc(str(t.get('detail') or t.get('ts') or '')[:120])}</td></tr>"
            )
    if not rt_rows:
        rt_rows = "<tr><td colspan='3' class='muted'>No active threats detected</td></tr>"

    control_panel = ""
    if control:
        control_panel = f"""
  <div class="section card" id="control">
    <h2>What you can do here</h2>
    <p class="hint">These buttons are safe for day-to-day use. Full hunts and firewall changes stay on the command line.</p>

    <div class="action-group">
      <div class="action-label">Reports for the client</div>
      <div class="actions">
        <a class="btn btn-pdf" id="btn-pdf-report" href="/api/report/pdf?type=client&amp;token={esc(token)}" target="_blank" rel="noopener">📄 Client report (easy to read)</a>
        <a class="btn secondary" href="/api/report/technical?token={esc(token)}" target="_blank" rel="noopener">🔧 Technical report (for IT)</a>
      </div>
    </div>

    <div class="action-group">
      <div class="action-label">Check the system</div>
      <div class="actions">
        <button class="btn" onclick="runAction('refresh')">🔄 Refresh this page data</button>
        <button class="btn secondary" onclick="runAction('doctor')">🩺 Health check (doctor)</button>
        <button class="btn secondary" onclick="runAction('service-status')">⚙️ Service status</button>
        <button class="btn secondary" onclick="runAction('go-live-status')">🚀 Go-live status</button>
        <button class="btn secondary" onclick="runAction('visibility')">👁️ Scan visibility</button>
      </div>
    </div>

    <div class="action-group">
      <div class="action-label">Alerts &amp; quiet hours</div>
      <div class="actions">
        <button class="btn secondary" onclick="runAction('quiet-on')"> Quiet mode ON</button>
        <button class="btn secondary" onclick="runAction('quiet-off')"> Quiet mode OFF</button>
        <button class="btn secondary" onclick="ackAllCritical()">✅ Clear all critical alerts</button>
        <button class="btn secondary" onclick="runAction('ops')">📊 Refresh ops numbers</button>
      </div>
    </div>

    <div class="action-group">
      <div class="action-label">Field tools</div>
      <div class="actions">
        <button class="btn secondary" onclick="runAction('field-soak')">Field-soak check</button>
      </div>
    </div>

    <div id="action-out" class="outbox" role="status">Ready — results show here.</div>
  </div>
"""
    else:
        control_panel = """
  <div class="section card" id="control"><h2>View only</h2>
    <p class="hint">This dashboard is in <b>view-only</b> mode. Ask TrinTech to enable controls if you need buttons here.</p>
  </div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <link rel="icon" type="image/png" href="/api/assets/logo?token={esc(token)}"/>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SENTINEL Dashboard</title>
<style>
:root {{
  --bg:#0b1220; --panel:#121a2b; --border:#1e2a40; --text:#e8eef9; --muted:#8b9bb4;
  --accent:#3b82f6; --good:#22c55e; --warn:#f59e0b; --bad:#ef4444; --crit:#f43f5e;
}}
* {{ box-sizing:border-box; }}
.brand-row {{ display:flex; align-items:center; gap:.75rem; }}
.brand-logo {{ width:48px; height:48px; border-radius:50%; background:#0b1f3a; object-fit:cover; border:2px solid #0e7c7b; flex-shrink:0; }}
body {{
  margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  background: radial-gradient(1200px 600px at 10% -10%, #1a2744 0%, var(--bg) 55%);
  color:var(--text); min-height:100vh;
  line-height:1.45;
}}
.hero {{
  border-radius:16px; padding:1.15rem 1.25rem; margin-bottom:1rem;
  border:1px solid var(--border); background:var(--panel);
}}
.hero-good {{ border-color:rgba(34,197,94,.45); box-shadow:0 0 0 1px rgba(34,197,94,.12); }}
.hero-warn {{ border-color:rgba(245,158,11,.45); box-shadow:0 0 0 1px rgba(245,158,11,.12); }}
.hero-bad {{ border-color:rgba(244,63,94,.5); box-shadow:0 0 0 1px rgba(244,63,94,.15); }}
.hero-title {{ font-size:1.35rem; font-weight:700; margin:0 0 .35rem; }}
.hero-good .hero-title {{ color:var(--good); }}
.hero-warn .hero-title {{ color:var(--warn); }}
.hero-bad .hero-title {{ color:var(--crit); }}
.hero-detail {{ color:var(--muted); margin:0 0 .75rem; font-size:.95rem; }}
.hero-chips {{ display:flex; flex-wrap:wrap; gap:.4rem; }}
.chip {{
  font-size:.75rem; color:var(--text); background:rgba(148,163,184,.12);
  border:1px solid var(--border); border-radius:999px; padding:.25rem .65rem;
}}
.hint {{ color:var(--muted); font-size:.88rem; margin:.15rem 0 .75rem; }}
.action-group {{ margin:1rem 0 1.15rem; }}
.action-label {{
  font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted);
  margin:0 0 .45rem;
}}
.actions {{ display:flex; flex-wrap:wrap; gap:.5rem; }}
.btn {{
  display:inline-flex; align-items:center; justify-content:center; gap:.35rem;
  min-height:42px; padding:.55rem 1rem; border-radius:10px; border:1px solid transparent;
  background:var(--accent); color:#fff; font-weight:600; font-size:.9rem;
  cursor:pointer; text-decoration:none; line-height:1.2;
}}
.btn:hover {{ filter:brightness(1.08); }}
.btn.secondary {{
  background:rgba(148,163,184,.12); color:var(--text); border-color:var(--border);
}}
.btn.btn-pdf {{ background:#0e7c7b; }}
.outbox {{
  margin-top:.85rem; padding:.85rem 1rem; border-radius:10px;
  background:#0a101c; border:1px solid var(--border); color:#cbd5e1;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size:.8rem; white-space:pre-wrap; word-break:break-word; min-height:2.5rem;
}}
.topnav a {{
  display:inline-block; padding:.35rem .55rem; margin:0 .15rem .25rem 0;
  border-radius:8px; background:rgba(59,130,246,.08);
}}
.topnav a:hover {{ background:rgba(59,130,246,.18); }}
@media (max-width:640px) {{
  header {{ padding:.85rem 1rem; }}
  .wrap {{ padding:.85rem; }}
  .btn {{ width:100%; }}
  .actions {{ flex-direction:column; }}
  .metric {{ font-size:1.25rem; }}
  .hero-title {{ font-size:1.15rem; }}
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
.badge.bad {{ background:rgba(239,68,68,.25); color:#fb7185; }}
.badge.elev {{ background:rgba(234,179,8,.18); color:#facc15; }}
.badge.info {{ background:rgba(34,211,238,.15); color:#22d3ee; }}
td.sev-CRITICAL {{ color:#e879f9; font-weight:700; }}
td.sev-HIGH {{ color:#f87171; font-weight:600; }}
td.sev-MEDIUM {{ color:#fbbf24; }}
td.sev-LOW {{ color:#4ade80; }}
tr.row-CRITICAL {{ background:rgba(244,63,94,.08); }}
tr.row-HIGH {{ background:rgba(239,68,68,.06); }}

.crit {{ color:var(--crit); font-weight:600; }}
table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
th, td {{ text-align:left; padding:.4rem .35rem; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.78rem; color:#c7d2fe; }}
.actions {{ display:flex; flex-wrap:wrap; gap:.45rem; margin-top:.5rem; }}
.btn-pdf {{ background:linear-gradient(135deg,#0E7C7B,#0B5F5E) !important; color:#fff !important; font-weight:700; border:none; padding:.55rem 1rem; }}
.btn-pdf:hover {{ filter:brightness(1.08); }}
.report-links a {{ color:#7dd3d0; margin-right:.75rem; }}
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
  <div class="brand-row">
    <img class="brand-logo" src="/api/assets/logo?token={esc(token)}" alt="TrinTech" width="48" height="48"/>
    <div>
    <h1>SENTINEL protection dashboard</h1>
    <div class="meta">{esc(data.get('host'))} · {esc(data.get('local_ip'))} · v{esc(data.get('version'))} · {esc(str(data.get('ts') or '')[:19])}Z</div>
    <nav class="topnav">
      <a href="#status-hero">Status</a>
      <a href="#overview">At a glance</a>
      <a href="#critical">Critical</a>
      <a href="#alerts">Alerts</a>
      <a href="#fleet">Network</a>
      <a href="#control">Actions</a>
      <a href="#reports">Reports</a>
    </nav>
    </div>
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
  <div class="hero {hero_class}" id="status-hero">
    <div class="hero-title">{esc(hero_status)}</div>
    <div class="hero-detail">{esc(hero_detail)}</div>
    <div class="hero-chips">
      <span class="chip">Host: {esc(data.get('host'))}</span>
      <span class="chip">IP: {esc(data.get('local_ip'))}</span>
      <span class="chip">v{esc(data.get('version'))}</span>
      <span class="chip">Devices: {esc((_fleet.get('count') if _fleet else None) or (data.get('visibility') or {}).get('devices') or 0)}</span>
      <span class="chip">Canaries: {esc((_can.get('alive') if isinstance(_can, dict) else 0))}/{esc((_can.get('total') if isinstance(_can, dict) else 0))}</span>
      <span class="chip">{"Controls on" if control else "View only"}</span>
    </div>
  </div>

  <div class="card section" id="realtime">
    <h2>Live threats <span id="rt-live" class="badge on">LIVE</span></h2>
    <p class="hint">What Sentinel sees right now on this machine.</p>
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
      <a class="btn secondary" href="/api/realtime">Realtime JSON</a>
    </div>
  </div>
  <div class="grid" id="overview">
    <div class="card"><h2>Protection cycles</h2><div class="metric">{esc(hunt.get('cycles', 0))}</div>
      <div class="muted">last {esc(hunt.get('last_cycle_sec', '—'))}s · ok={esc(hunt.get('last_ok'))}</div></div>
    <div class="card"><h2>Critical alerts</h2><div class="metric" style="color:var(--crit)">{esc(crit.get('open_count', 0))}</div>
      <div class="muted">need a human to clear</div></div>
    <div class="card"><h2>All alerts</h2><div class="metric">{esc(data.get('alert_total', 0))}</div>
      <div class="muted">offline q {esc(ops.get('offline_queue', 0))}</div></div>
    <div class="card"><h2>Devices on network</h2><div class="metric">{esc((data.get('fleet') or {}).get('count') or vis.get('devices', 0))}</div>
    <div class="meta">scan={esc((data.get('fleet') or {}).get('scan_method'))} · canaries local/pending={esc((data.get('fleet') or {}).get('canary_planted'))}/{esc((data.get('fleet') or {}).get('canary_pending_agent'))}</div>
    <div class="meta">pending operator review: {esc((data.get('fleet') or {}).get('pending_review') or 0)}</div>
      <div class="muted">ARP live {esc(vis.get('live_arp', 0))}</div></div>
    <div class="card"><h2>Running processes</h2><div class="metric">{esc(vis.get('processes', 0))}</div>
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

  
  <div class="section card" id="reports">
    <h2>📄 PDF reports</h2>
    <p class="muted">Tap a button to open the report immediately in this browser. You can download from the viewer.</p>
    <div class="actions">
      <a class="btn btn-pdf" href="/api/report/pdf?token={esc(token)}" target="_blank" rel="noopener">Generate &amp; view client PDF</a>
      <a class="btn secondary" href="/api/report/technical?token={esc(token)}" target="_blank" rel="noopener">Technical PDF</a>
    </div>
  </div>


  <div class="section card" id="fleet">
    <h2>Network fleet</h2>
    <p class="muted">All discovered devices on the client network. Local host gets canary files; other hosts need a Sentinel agent for file canaries. High-severity items can wait in operator review before client-critical flags.</p>
    <div class="meta">Hosts: {esc(fleet.get('count', 0))} · Scan: {esc(fleet.get('scan_method'))} · Local canaries: {esc(fleet.get('canary_planted'))} · Agent canaries pending: {esc(fleet.get('canary_pending_agent'))} · Review queue: {esc(fleet.get('pending_review', 0))}</div>
    <pre style="max-height:240px;overflow:auto;font-size:11px">{esc(fleet_json)}</pre>
  </div>

{control_panel}

  <div class="section card">
    <h2>API</h2>
    <div class="actions">
      <a class="btn secondary" href="/">Reload UI</a>
      <a class="btn secondary" href="/api/status">Full JSON</a>
      <a class="btn secondary" href="/api/critical">Critical JSON</a>
      <a class="btn secondary" href="/api/go-live">Go-live JSON</a>
    </div>
  </div>
</div>
<footer>TrinTech Digital Defense · Authorized defensive use only · Token required</footer>
<script>
const TOKEN = "{esc(token)}";
function authHeaders(json) {{
  const h = {{"Authorization": "Bearer " + TOKEN}};
  if (json) h["Content-Type"] = "application/json";
  return h;
}}

async function ackCritical(id) {{
  if (!confirm("ACK critical " + id + "?")) return;
  const r = await fetch("/api/critical/ack", {{
    method: "POST", headers: authHeaders(true),
    body: JSON.stringify({{id}})
  }});
  const j = await r.json();
  if (!r.ok || !j.ok) {{ alert("Failed: " + (j.error || r.status)); return; }}
  location.reload();
}}
async function ackAllCritical() {{
  if (!confirm("ACK ALL open criticals?")) return;
  const r = await fetch("/api/critical/ack-all", {{
    method: "POST", headers: authHeaders(true), body: "{{}}"
  }});
  const j = await r.json();
  if (!r.ok || !j.ok) {{ alert("Failed: " + (j.error || r.status)); return; }}
  location.reload();
}}
async function runAction(name) {{
  const out = document.getElementById("action-out");
  if (out) out.textContent = "Running " + name + "...";
  if (name === "refresh") {{ location.reload(); return; }}
  try {{
    const r = await fetch("/api/action", {{
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({{action: name}})
    }});
    let j = null;
    const text = await r.text();
    try {{ j = JSON.parse(text); }} catch (e) {{
      if (out) out.textContent = "Bad response (" + r.status + "): " + text.slice(0, 500);
      alert("Action failed (" + r.status + "). See status box.");
      return;
    }}
    if (!r.ok || (j && j.ok === false)) {{
      const err = (j && (j.error || j.message)) || ("HTTP " + r.status);
      if (out) out.textContent = "FAILED: " + err + "\n\n" + text.slice(0, 1500);
      alert("Action failed: " + err);
      return;
    }}
    // PDF / downloadable reports — open for viewing + download links
    if (j && (j.download || j.downloads || j.path)) {{
      let links = [];
      if (j.download) links.push(j.download);
      if (Array.isArray(j.downloads)) links.push.apply(links, j.downloads);
      // unique
      links = links.filter(function(v, i, a) {{ return a.indexOf(v) === i; }});
      // attach token for top-level navigation (Bearer not sent on <a> / window.open)
      function withToken(u) {{
        if (!u) return u;
        if (u.indexOf("token=") >= 0) return u;
        return u + (u.indexOf("?") >= 0 ? "&" : "?") + "token=" + encodeURIComponent(TOKEN);
      }}
      links = links.map(withToken);
      if (out) {{
        out.textContent = "OK — report ready. Use View / Download below.";
      }}
      let box = document.getElementById("report-links");
      if (!box) {{
        box = document.createElement("div");
        box.id = "report-links";
        box.className = "report-links";
        if (out && out.parentNode) out.parentNode.insertBefore(box, out.nextSibling);
      }}
      let viewer = document.getElementById("pdf-viewer-wrap");
      if (!viewer) {{
        viewer = document.createElement("div");
        viewer.id = "pdf-viewer-wrap";
        viewer.className = "pdf-viewer-wrap";
        if (box.parentNode) box.parentNode.insertBefore(viewer, box.nextSibling);
      }}
      box.innerHTML = links.map(function(u, i) {{
        const label = (i === 0) ? "Client / primary report" : ("Report " + (i + 1));
        return '<div class="report-row">'
          + '<a class="btn btn-pdf" href="' + u + '" target="_blank" rel="noopener">View ' + label + '</a> '
          + '<a class="btn secondary" href="' + u + '" download>Download</a>'
          + '</div>';
      }}).join("");
      // Inline viewer for first PDF
      if (links[0]) {{
        viewer.innerHTML = '<p class="muted">Preview (if the browser supports PDF)</p>'
          + '<iframe class="pdf-frame" title="PDF report" src="' + links[0] + '"></iframe>';
        // Also open a tab for mobile browsers that block iframes
        try {{ window.open(links[0], "_blank"); }} catch (e) {{}}
      }}
      return;
    }}
    if (out) out.textContent = JSON.stringify(j, null, 2);
  }} catch (e) {{
    if (out) out.textContent = "Error: " + e;
    alert("Action error: " + e);
  }}
}}
async function toggleControl(want) {{
  if (typeof want !== "boolean") {{
    const el = document.getElementById("ctrl-label");
    const cur = el && el.getAttribute("data-control") === "true";
    want = !cur;
  }}
  try {{
    const r = await fetch("/api/control-mode", {{
      method: "POST",
      headers: authHeaders(true),
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
  const map = {{CRITICAL:"bad", HIGH:"warn", ELEVATED:"elev", WATCH:"info", CLEAR:"on"}};
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
      const sev = String(t.severity || "MEDIUM").toUpperCase();
      rows += "<tr class=\"row-" + sev + "\"><td class=\"sev-" + sev + "\">" + sev +
              "</td><td class=\"crit\">" + (t.type||"") +
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
    const r = await fetch("/api/realtime?scan=1", {{ headers: authHeaders(false) }});
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
    allow_control = False  # safe class default

    def log_message(self, fmt, *args):
        pass

    def _auth_ok(self) -> bool:
        """Prefer Authorization Bearer, then cookie, then query token (deprecated)."""
        # 1) Bearer
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer ") and auth[7:].strip() == self.token:
            return True
        # 2) Cookie sentinel_token=
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("sentinel_token="):
                if part.split("=", 1)[1].strip() == self.token:
                    return True
        # 3) Query string (deprecated — still accepted for first page load)
        q = parse_qs(urlparse(self.path).query)
        t = (q.get("token") or [""])[0]
        if t and t == self.token:
            return True
        return False


    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra_headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
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
            self._send(401, b'{"ok":false,"error":"unauthorized","hint":"Authorization: Bearer <token> or initial ?token="}', "application/json")
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

        # One-click PDF: generate + stream (works without JS / POST)

        if path in ("/api/assets/logo", "/logo.png", "/favicon.ico"):
            logo = _logo_asset()
            if not logo:
                self._send(404, b'{"ok":false,"error":"logo missing"}', "application/json")
                return
            body = logo.read_bytes()
            ctype = "image/png"
            self._send(200, body, ctype, extra_headers={"Cache-Control": "public, max-age=3600"})
            return

        if path in ("/api/report/pdf", "/api/report/client", "/api/report/generate", "/api/report/tech", "/api/report/technical"):
            try:
                from urllib.parse import parse_qs
                qs = parse_qs(urlparse(self.path).query)
                kind = (qs.get("type") or qs.get("kind") or ["client"])[0].lower()
                if path.endswith("/tech") or path.endswith("/technical") or kind in ("tech", "technical", "operator"):
                    kind = "technical"
                else:
                    kind = "client"
                reports = _reports_dir()
                reports.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                if kind == "technical":
                    from modules.technical_report import generate_technical_pdf
                    out_path = reports / f"Sentinel_Technical_{ts}.pdf"
                    result = generate_technical_pdf(out_path=out_path)
                else:
                    from modules.client_report import generate_client_pdf
                    out_path = reports / f"Client_Report_{ts}.pdf"
                    cname = (_cfg().get("dashboard") or {}).get("client_name") or _cfg().get("client_name")
                    result = generate_client_pdf(out_path=out_path, client_name=cname)
                if not result.get("ok"):
                    self._send(500, json.dumps({"ok": False, "error": result.get("error") or "generate failed"}).encode(), "application/json")
                    return
                path_out = Path(str(result.get("path") or out_path))
                if not path_out.is_file():
                    self._send(500, b'{"ok":false,"error":"pdf missing after generate"}', "application/json")
                    return
                body = path_out.read_bytes()
                extra = {
                    "Content-Disposition": f'inline; filename="{path_out.name}"',
                    "Cache-Control": "no-store",
                    "X-Sentinel-Report": path_out.name,
                    "X-Sentinel-Report-Type": kind,
                }
                self._send(200, body, "application/pdf", extra_headers=extra)
            except Exception as e:
                logging.getLogger("sentinel").exception("GET report pdf")
                self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
            return


        if path in ("/api/report/technical", "/api/report/tech"):
            try:
                result = _generate_dashboard_pdfs("tech-report")
                if not result.get("ok"):
                    # fallback client-style
                    from modules.client_report import generate_client_pdf
                    reports = _reports_dir()
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    out_path = reports / f"Sentinel_Technical_{ts}.pdf"
                    result2 = generate_client_pdf(out_path=out_path)
                    if not result2.get("ok"):
                        self._send(500, json.dumps({"ok": False, "error": result.get("error") or result2.get("error")}).encode(), "application/json")
                        return
                    path_out = Path(str(result2.get("path") or out_path))
                else:
                    # pick first generated path
                    gens = result.get("generated") or []
                    path_out = Path((gens[0] or {}).get("path") or result.get("path") or "")
                if not path_out.is_file():
                    self._send(404, b'{"ok":false,"error":"technical pdf not found"}', "application/json")
                    return
                body = path_out.read_bytes()
                extra = {
                    "Content-Disposition": f'inline; filename="{path_out.name}"',
                    "Cache-Control": "no-store",
                }
                self._send(200, body, "application/pdf", extra_headers=extra)
            except Exception as e:
                logging.getLogger("sentinel").exception("GET tech pdf")
                self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
            return

        if path in ("/api/report/download", "/api/reports/download"):
            q = parse_qs(urlparse(self.path).query)
            name = (q.get("name") or [""])[0]
            # path traversal guard
            name = Path(name).name
            if not name or not name.endswith(".pdf"):
                self._send(400, b'{"ok":false,"error":"name required (.pdf)"}', "application/json")
                return
            # search reports dir then data dir
            candidates = [
                _reports_dir() / name,
                _data() / name,
                _data() / "reports" / name,
            ]
            target = next((c for c in candidates if c.is_file()), None)
            if not target:
                self._send(404, b'{"ok":false,"error":"report not found"}', "application/json")
                return
            try:
                body = target.read_bytes()
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
                return
            extra = {
                "Content-Disposition": f'inline; filename="{name}"',
                "Cache-Control": "no-store",
            }
            self._send(200, body, "application/pdf", extra_headers=extra)
            return
        if path.startswith("/api/"):
            self._send(200, json.dumps(data, indent=2, default=str).encode(), "application/json")
            return
        # Prefer cookie for subsequent requests (H-04 mitigation)
        body = _html(self.token, data).encode("utf-8")
        extra = {
            "Set-Cookie": f"sentinel_token={self.token}; Path=/; HttpOnly; SameSite=Strict",
            "X-Token-Deprecation": "Prefer Authorization: Bearer; query token is deprecated",
        }
        self._send(200, body, "text/html; charset=utf-8", extra_headers=extra)

    def do_POST(self):
        if not self._auth_ok():
            self._send(401, b'{"ok":false,"error":"unauthorized"}', "application/json")
            return
        path = urlparse(self.path).path
        body_in = self._read_json_body()

        # Control-mode: only allow *disabling* controls with the shareable token.
        # Enabling controls requires dashboard.allow_control already true in config
        # or explicit role=admin with allow_control already granted by an operator on disk.
        if "control-mode" in path or path.rstrip("/").endswith("control-mode"):
            want = body_in.get("allow_control")
            if want is None:
                want = not self.allow_control
            want = bool(want)
            cfg = _cfg()
            dash = cfg.setdefault("dashboard", {})
            current = bool(dash.get("allow_control", False))
            role = str(dash.get("role") or "viewer").lower()
            # Escalation denied: token alone cannot turn controls ON
            if want and not current:
                self._send(
                    403,
                    json.dumps({
                        "ok": False,
                        "error": "cannot enable controls via token alone; set dashboard.allow_control=true in config.json on the host",
                    }).encode(),
                    "application/json",
                )
                return
            # Allow turning OFF for safety, or confirming ON if already enabled
            dash["allow_control"] = want
            cfg["dashboard"] = dash
            _save_cfg(cfg)
            self.allow_control = want
            _Handler.allow_control = want
            self._send(200, json.dumps({"ok": True, "allow_control": want, "role": role}).encode(), "application/json")
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
                "pdf-report": None,       # handled below — client + technical
                "client-report": None,   # plain-language client PDF
                "tech-report": None,     # technical PDF via CLI
            }
            # One-push / dedicated PDF report generation (non-destructive)
            if action in ("pdf-report", "client-report", "tech-report"):
                try:
                    result = _generate_dashboard_pdfs(action)
                    self._send(200 if result.get("ok") else 500,
                               json.dumps(result, default=str).encode(),
                               "application/json")
                except Exception as e:
                    logging.getLogger("sentinel").exception("dashboard pdf-report")
                    self._send(500, json.dumps({"ok": False, "error": str(e)}).encode(), "application/json")
                return
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



def _reports_dir() -> Path:
    d = _data() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d



def _generate_dashboard_pdfs(action: str = "pdf-report") -> dict:
    """Generate client and/or technical PDFs with live data; always land under reports/."""
    import logging
    log = logging.getLogger("sentinel")
    reports = _reports_dir()
    reports.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out: dict = {"ok": True, "action": action, "generated": [], "downloads": []}
    cfg = _cfg()
    cname = (cfg.get("dashboard") or {}).get("client_name") or cfg.get("client_name")

    def _rel(path: Path) -> str:
        return f"/api/report/download?name={path.name}"

    if action in ("pdf-report", "client-report"):
        try:
            from modules.client_report import generate_client_pdf
            client_path = reports / f"Client_Report_{ts}.pdf"
            r = generate_client_pdf(out_path=client_path, client_name=cname)
            if r.get("ok"):
                path = Path(str(r.get("path") or client_path))
                if path.is_file() and path.parent.resolve() != reports.resolve():
                    dest = reports / path.name
                    dest.write_bytes(path.read_bytes())
                    path = dest
                out["generated"].append({"type": "client", "path": str(path)})
                out["path"] = str(path)
                out["download"] = _rel(path)
                out["downloads"].append(out["download"])
                out["client"] = {"ok": True, "path": str(path), "headline": r.get("headline"), "level": r.get("level")}
            else:
                out["client_error"] = r.get("error") or "client PDF failed"
                if action == "client-report":
                    out["ok"] = False
                    out["error"] = out["client_error"]
                    return out
        except Exception as e:
            log.exception("client PDF")
            out["client_error"] = str(e)
            if action == "client-report":
                out["ok"] = False
                out["error"] = str(e)
                return out

    if action in ("pdf-report", "tech-report"):
        try:
            from modules.technical_report import generate_technical_pdf
            tech_path = reports / f"Sentinel_Technical_{ts}.pdf"
            r = generate_technical_pdf(out_path=tech_path)
            if r.get("ok"):
                path = Path(str(r.get("path") or tech_path))
                if path.is_file() and path.parent.resolve() != reports.resolve():
                    dest = reports / path.name
                    dest.write_bytes(path.read_bytes())
                    path = dest
                out["generated"].append({"type": "technical", "path": str(path)})
                dl = _rel(path)
                if dl not in out["downloads"]:
                    out["downloads"].append(dl)
                if action == "tech-report" or not out.get("download"):
                    out["download"] = dl
                    out["path"] = str(path)
                out["technical"] = {"ok": True, "path": str(path), "alerts": r.get("alerts"), "fleet": r.get("fleet")}
            else:
                out["tech_error"] = r.get("error") or "technical PDF failed"
                if action == "tech-report":
                    out["ok"] = False
                    out["error"] = out["tech_error"]
                    return out
        except Exception as e:
            log.exception("technical PDF")
            out["tech_error"] = str(e)
            if action == "tech-report":
                out["ok"] = False
                out["error"] = str(e)
                return out

    if not out["generated"]:
        out["ok"] = False
        out["error"] = out.get("client_error") or out.get("tech_error") or "no PDF produced"
    out["message"] = (
        "PDF ready. Client report is plain-language for owners; "
        "technical report is operator detail from live host data."
    )
    return out




def start_dashboard(port: int | None = None, bind: str | None = None):
    token, cfg_port, dash = ensure_token()
    port = int(port or cfg_port or DEFAULT_PORT)
    bind = bind or dash.get("bind") or "127.0.0.1"
    if bind in ("0.0.0.0", "::", "*") and not dash.get("allow_public_bind"):
        print("[!] Refusing public bind without dashboard.allow_public_bind=true — using 127.0.0.1")
        bind = "127.0.0.1"
    _Handler.token = token
    _Handler.allow_control = bool(dash.get("allow_control", False))
    try:
        from modules.rbac import must_change_password
        cfg = _cfg()
        if "password" in (cfg.get("dashboard") or {}) and must_change_password(cfg):
            print("[!] Default/empty dashboard.password — change it (doctor will FAIL on password check)")
    except Exception as e:
        logging.getLogger("sentinel").debug("rbac check: %s", e)
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
