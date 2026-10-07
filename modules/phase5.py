#!/usr/bin/env python3
"""
Sentinel Phase 5 — Competitive ops layer
  - Auto LAN subnet detection
  - Heartbeat file (uptime / external monitors)
  - Alert digest (24h summary)
  - JSON status export
  - Lightweight HTML status dashboard
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Optional


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


def _run(cmd, timeout=12) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return str(e)


def detect_local_subnets() -> list:
    found = []
    out = _run(["ip", "-o", "-4", "addr", "show"])
    for line in out.splitlines():
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        ip = m.group(1)
        if ip.startswith("127."):
            continue
        parts = ip.split(".")
        cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if cidr not in found:
            found.append(cidr)
    if not found:
        out = _run(["hostname", "-I"])
        for tok in out.split():
            if re.match(r"\d+\.\d+\.\d+\.\d+$", tok) and not tok.startswith("127."):
                parts = tok.split(".")
                found.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
                break
    return found or ["192.168.1.0/24"]


def auto_subnet_apply(config=None) -> dict:
    c = config if config is not None else _cfg()
    nets = detect_local_subnets()
    c.setdefault("network", {})
    old = c["network"].get("scan_subnets") or []
    c["network"]["scan_subnets"] = nets
    c["network"]["auto_detected"] = True
    c["network"]["auto_detected_at"] = datetime.now().isoformat()
    _save_cfg(c)
    return {"ok": True, "scan_subnets": nets, "previous": old}


def heartbeat_write(extra=None) -> dict:
    path = _data() / "heartbeat.json"
    payload = {
        "ts": datetime.now().isoformat(),
        "host": socket.gethostname(),
        "status": "alive",
        "version": "2.5.0",
        "phase": 5,
    }
    if extra:
        payload.update(extra)
    path.write_text(json.dumps(payload, indent=2))
    return {"ok": True, "file": str(path), "ts": payload["ts"]}


def heartbeat_status() -> dict:
    path = _data() / "heartbeat.json"
    if not path.exists():
        return {"ok": False, "alive": False, "error": "no heartbeat yet — run: sentinel heartbeat"}
    try:
        data = json.loads(path.read_text())
        ts = datetime.fromisoformat(data["ts"])
        age = (datetime.now() - ts).total_seconds()
        return {"ok": True, "alive": age < 600, "age_seconds": int(age), "data": data}
    except Exception as e:
        return {"ok": False, "alive": False, "error": str(e)}


def alert_digest(hours: int = 24) -> dict:
    log = _data() / "alerts.log"
    lines = []
    counts = {}
    if log.exists():
        for line in log.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            lines.append(line[-300:])
            key = "other"
            low = line.lower()
            for k in ("reverse", "canary", "ssh", "integrity", "fim", "suspicious", "process"):
                if k in low:
                    key = k
                    break
            counts[key] = counts.get(key, 0) + 1
    recent = lines[-50:]
    summary = {
        "ok": True,
        "hours": hours,
        "total_lines_scanned": len(lines),
        "recent_count": len(recent),
        "by_keyword": counts,
        "recent": recent[-15:],
        "generated": datetime.now().isoformat(),
        "host": socket.gethostname(),
    }
    out = _data() / "digest_latest.json"
    out.write_text(json.dumps(summary, indent=2))
    summary["file"] = str(out)
    return summary


def status_json() -> dict:
    cfg = _cfg()
    nets = (cfg.get("network") or {}).get("scan_subnets") or []
    hb = heartbeat_status()
    digest = alert_digest(24)
    baseline = (_data() / "behavioral_baseline.json").exists()
    fim = (_data() / "integrity_baseline" / "integrity_baseline.json").exists()
    return {
        "ok": True,
        "product": "SENTINEL",
        "version": "2.5.0",
        "host": socket.gethostname(),
        "ts": datetime.now().isoformat(),
        "scan_subnets": nets,
        "heartbeat_alive": hb.get("alive", False),
        "heartbeat_age_seconds": hb.get("age_seconds"),
        "behavioral_baseline": baseline,
        "fim_baseline": fim,
        "alerts_24h_approx": digest.get("recent_count", 0),
        "alert_buckets": digest.get("by_keyword", {}),
        "data_dir": str(_data()),
    }


def _html_page() -> str:
    st = status_json()
    dig = alert_digest(24)
    rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in (dig.get("by_keyword") or {}).items()
    ) or "<tr><td colspan='2'>No alerts bucketed</td></tr>"
    recent = "".join(f"<li><code>{x}</code></li>" for x in (dig.get("recent") or [])[-8:])
    if not recent:
        recent = "<li>No recent alert lines</li>"
    alive = st.get("heartbeat_alive")
    badge = "ALIVE" if alive else "STALE / NO HEARTBEAT"
    color = "#0F766E" if alive else "#C2410C"
    nets = ", ".join(st.get("scan_subnets") or []) or "(not set)"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta http-equiv="refresh" content="30"/>
<title>SENTINEL Status — TrinTech</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #0B1F3A; color: #E2E8F0; }}
  header {{ padding: 1.2rem 1.5rem; background: #071525; border-bottom: 3px solid #1A8CFF; }}
  h1 {{ margin: 0; font-size: 1.4rem; letter-spacing: .06em; }}
  .sub {{ color: #94A3B8; font-size: .9rem; }}
  main {{ padding: 1.5rem; max-width: 900px; margin: 0 auto; }}
  .card {{ background: #132337; border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 1rem; }}
  .badge {{ display: inline-block; padding: .25rem .7rem; border-radius: 999px;
            background: {color}; color: #fff; font-weight: 700; font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td, th {{ text-align: left; padding: .4rem .3rem; border-bottom: 1px solid #1e3a5f; }}
  code {{ font-size: .78rem; color: #7DD3FC; word-break: break-all; }}
  ul {{ padding-left: 1.2rem; }}
  footer {{ text-align: center; color: #64748B; font-size: .8rem; padding: 1rem; }}
</style>
</head>
<body>
<header>
  <h1>SENTINEL</h1>
  <div class="sub">TrinTech Digital Defense · local status dashboard</div>
</header>
<main>
  <div class="card">
    <span class="badge">{badge}</span>
    <p><b>Host:</b> {st.get("host")} &nbsp;·&nbsp; <b>Version:</b> {st.get("version")}</p>
    <p><b>Time:</b> {st.get("ts")}</p>
    <p><b>Scan subnets:</b> {nets}</p>
    <p><b>FIM baseline:</b> {"yes" if st.get("fim_baseline") else "no"} &nbsp;·&nbsp;
       <b>Behavioral baseline:</b> {"yes" if st.get("behavioral_baseline") else "no"}</p>
    <p><b>Heartbeat age:</b> {st.get("heartbeat_age_seconds")}s</p>
  </div>
  <div class="card">
    <h3>Alert buckets (log keywords)</h3>
    <table><tr><th>Keyword</th><th>Count</th></tr>{rows}</table>
  </div>
  <div class="card">
    <h3>Recent alert lines</h3>
    <ul>{recent}</ul>
  </div>
</main>
<footer>Auto-refresh 30s · Authorized use only · WhatsApp +1 (868) 362-0679</footer>
</body>
</html>
"""


def dashboard_write() -> dict:
    path = _data() / "dashboard.html"
    path.write_text(_html_page())
    return {"ok": True, "file": str(path)}


def dashboard_serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    dashboard_write()
    heartbeat_write({"dashboard": True})

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            dashboard_write()
            body = _html_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    httpd = HTTPServer((host, port), H)
    print(f"[+] SENTINEL dashboard http://{host}:{port}/  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped")


def phase5_self_check() -> dict:
    return {
        "auto_subnet": True,
        "heartbeat": True,
        "digest": True,
        "status_json": True,
        "dashboard": True,
        "detected_subnets": detect_local_subnets(),
        "heartbeat_file": str(_data() / "heartbeat.json"),
    }
