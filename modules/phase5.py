#!/usr/bin/env python3
"""Sentinel Phase 5 — hygiene, WhatsApp digest, heartbeat, dashboard, autosubnet."""
from __future__ import annotations
import hashlib, json, os, re, socket, subprocess, urllib.parse, urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
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
def _save_cfg(c: dict) -> None:
    p = _home() / "config.json"; p.parent.mkdir(parents=True, exist_ok=True)
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
        if not m: continue
        ip = m.group(1)
        if ip.startswith("127."): continue
        parts = ip.split(".")
        cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if cidr not in found: found.append(cidr)
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

HYGIENE_FILE = "alert_hygiene.json"
DEFAULT_WINDOW_SEC = 900
DEFAULT_MAX_PER_KEY = 1

def _hygiene_load() -> dict:
    p = _data() / HYGIENE_FILE
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: pass
    return {"entries": {}, "suppressed_total": 0, "allowed_total": 0}

def _hygiene_save(state: dict) -> None:
    (_data() / HYGIENE_FILE).write_text(json.dumps(state, indent=2))

def _alert_key(alert_type: str, details: Any) -> str:
    raw = f"{alert_type}|{details}"
    if isinstance(details, dict):
        parts = [str(details.get(k, "")) for k in ("pid", "path", "ip", "command", "pattern", "user")]
        raw = f"{alert_type}|" + "|".join(parts)[:200]
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]

def hygiene_should_emit(alert_type: str, details: Any = None, window_sec: int = DEFAULT_WINDOW_SEC, max_per_key: int = DEFAULT_MAX_PER_KEY) -> dict:
    c = _cfg()
    hy = (c.get("phase5") or {}).get("hygiene") or {}
    if hy.get("enabled") is False:
        return {"allow": True, "reason": "hygiene_disabled", "key": None}
    window_sec = int(hy.get("window_sec", window_sec))
    max_per_key = int(hy.get("max_per_key", max_per_key))
    state = _hygiene_load()
    entries = state.setdefault("entries", {})
    now = datetime.now()
    key = _alert_key(alert_type or "GENERIC", details)
    pruned = {}
    for k, v in entries.items():
        try:
            ts = datetime.fromisoformat(v["last"])
            if (now - ts).total_seconds() < window_sec * 4:
                pruned[k] = v
        except Exception:
            continue
    entries = pruned
    state["entries"] = entries
    ent = entries.get(key)
    if not ent:
        entries[key] = {"count": 1, "first": now.isoformat(), "last": now.isoformat(), "type": alert_type}
        state["allowed_total"] = state.get("allowed_total", 0) + 1
        _hygiene_save(state)
        return {"allow": True, "reason": "first_seen", "key": key, "suppressed_total": state.get("suppressed_total", 0)}
    try:
        last = datetime.fromisoformat(ent["last"])
    except Exception:
        last = now - timedelta(seconds=window_sec + 1)
    age = (now - last).total_seconds()
    if age < window_sec and ent.get("count", 0) >= max_per_key:
        state["suppressed_total"] = state.get("suppressed_total", 0) + 1
        ent["suppressed"] = ent.get("suppressed", 0) + 1
        _hygiene_save(state)
        return {"allow": False, "reason": f"rate_limited_{int(age)}s_of_{window_sec}s", "key": key, "suppressed_total": state["suppressed_total"]}
    if age >= window_sec:
        ent["count"] = 1
    else:
        ent["count"] = ent.get("count", 0) + 1
    ent["last"] = now.isoformat()
    state["allowed_total"] = state.get("allowed_total", 0) + 1
    _hygiene_save(state)
    return {"allow": True, "reason": "allowed", "key": key, "suppressed_total": state.get("suppressed_total", 0)}

def hygiene_status() -> dict:
    state = _hygiene_load()
    return {"ok": True, "entries": len(state.get("entries") or {}), "allowed_total": state.get("allowed_total", 0), "suppressed_total": state.get("suppressed_total", 0), "file": str(_data() / HYGIENE_FILE)}

def hygiene_reset() -> dict:
    p = _data() / HYGIENE_FILE
    if p.exists(): p.unlink()
    return {"ok": True, "reset": True}

def ensure_hygiene_defaults(config=None) -> dict:
    c = config if config is not None else _cfg()
    p5 = c.setdefault("phase5", {})
    hy = p5.setdefault("hygiene", {})
    hy.setdefault("enabled", True)
    hy.setdefault("window_sec", DEFAULT_WINDOW_SEC)
    hy.setdefault("max_per_key", DEFAULT_MAX_PER_KEY)
    _save_cfg(c)
    return c

def heartbeat_write(extra: Optional[dict] = None) -> dict:
    path = _data() / "heartbeat.json"
    payload = {"ts": datetime.now().isoformat(), "host": socket.gethostname(), "status": "alive", "version": "2.5.0", "phase": 5, "source": (extra or {}).get("source", "manual")}
    if extra: payload.update(extra)
    path.write_text(json.dumps(payload, indent=2))
    return {"ok": True, "file": str(path), "ts": payload["ts"], "source": payload["source"]}

def heartbeat_status() -> dict:
    path = _data() / "heartbeat.json"
    if not path.exists():
        return {"ok": False, "alive": False, "error": "no heartbeat yet"}
    try:
        data = json.loads(path.read_text())
        ts = datetime.fromisoformat(data["ts"])
        age = (datetime.now() - ts).total_seconds()
        return {"ok": True, "alive": age < 600, "age_seconds": int(age), "data": data}
    except Exception as e:
        return {"ok": False, "alive": False, "error": str(e)}

def heartbeat_from_hunt() -> dict:
    return heartbeat_write({"source": "hunt"})

def alert_digest(hours: int = 24) -> dict:
    log = _data() / "alerts.log"
    lines, counts = [], {}
    if log.exists():
        for line in log.read_text(errors="ignore").splitlines():
            if not line.strip(): continue
            lines.append(line[-300:])
            key = "other"
            low = line.lower()
            for k in ("reverse", "canary", "ssh", "integrity", "fim", "suspicious", "process"):
                if k in low: key = k; break
            counts[key] = counts.get(key, 0) + 1
    recent = lines[-50:]
    hy = hygiene_status()
    summary = {"ok": True, "hours": hours, "total_lines_scanned": len(lines), "recent_count": len(recent), "by_keyword": counts, "recent": recent[-15:], "hygiene": {"suppressed_total": hy.get("suppressed_total", 0), "allowed_total": hy.get("allowed_total", 0)}, "generated": datetime.now().isoformat(), "host": socket.gethostname()}
    out = _data() / "digest_latest.json"
    out.write_text(json.dumps(summary, indent=2))
    summary["file"] = str(out)
    return summary

def format_digest_text(d: dict) -> str:
    buckets = d.get("by_keyword") or {}
    bucket_s = ", ".join(f"{k}:{v}" for k, v in buckets.items()) or "none"
    hy = d.get("hygiene") or {}
    return "\n".join(["SENTINEL digest", f"Host: {d.get('host')}", f"Lines: {d.get('recent_count')} (scan {d.get('total_lines_scanned')})", f"Buckets: {bucket_s}", f"Hygiene suppressed: {hy.get('suppressed_total', 0)}", f"Time: {d.get('generated')}", "— TrinTech Digital Defense"])

def ensure_whatsapp_defaults(config=None) -> dict:
    c = config if config is not None else _cfg()
    al = c.setdefault("alerting", {})
    wa = al.setdefault("whatsapp", {})
    wa.setdefault("enabled", False)
    wa.setdefault("provider", "callmebot")
    wa.setdefault("phone", "18683620679")
    wa.setdefault("apikey", "")
    wa.setdefault("digest_hours", 24)
    _save_cfg(c)
    return c

def whatsapp_send(text: str, phone: Optional[str] = None, apikey: Optional[str] = None) -> dict:
    c = ensure_whatsapp_defaults()
    wa = (c.get("alerting") or {}).get("whatsapp") or {}
    phone = re.sub(r"[^\d]", "", str(phone or wa.get("phone") or "18683620679"))
    apikey = apikey or wa.get("apikey") or ""
    if not apikey:
        return {"ok": False, "error": "Set alerting.whatsapp.apikey in ~/.sentinel/config.json (CallMeBot)"}
    q = urllib.parse.urlencode({"phone": phone, "text": text[:1500], "apikey": apikey})
    url = f"https://api.callmebot.com/whatsapp.php?{q}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return {"ok": True, "phone": phone, "response": body[:300]}
    except Exception as e:
        return {"ok": False, "error": str(e), "phone": phone}

def whatsapp_digest(hours: int = 24, force: bool = False) -> dict:
    c = ensure_whatsapp_defaults()
    wa = (c.get("alerting") or {}).get("whatsapp") or {}
    d = alert_digest(hours=hours)
    text = format_digest_text(d)
    if not force and not wa.get("enabled"):
        return {"ok": True, "sent": False, "reason": "whatsapp disabled — enable or use --force", "preview": text, "digest_file": d.get("file")}
    result = whatsapp_send(text)
    result["preview"] = text
    result["sent"] = result.get("ok", False)
    result["digest_file"] = d.get("file")
    return result

def status_json() -> dict:
    cfg = _cfg()
    nets = (cfg.get("network") or {}).get("scan_subnets") or []
    hb = heartbeat_status()
    digest = alert_digest(24)
    hy = hygiene_status()
    return {"ok": True, "product": "SENTINEL", "version": "2.5.0", "host": socket.gethostname(), "ts": datetime.now().isoformat(), "scan_subnets": nets, "heartbeat_alive": hb.get("alive", False), "heartbeat_age_seconds": hb.get("age_seconds"), "heartbeat_source": (hb.get("data") or {}).get("source"), "behavioral_baseline": (_data() / "behavioral_baseline.json").exists(), "fim_baseline": (_data() / "integrity_baseline" / "integrity_baseline.json").exists(), "alerts_24h_approx": digest.get("recent_count", 0), "alert_buckets": digest.get("by_keyword", {}), "hygiene_suppressed": hy.get("suppressed_total", 0), "data_dir": str(_data())}

def _html_page() -> str:
    st = status_json()
    dig = alert_digest(24)
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in (dig.get("by_keyword") or {}).items()) or "<tr><td colspan='2'>No alerts</td></tr>"
    recent = "".join(f"<li><code>{x}</code></li>" for x in (dig.get("recent") or [])[-8:]) or "<li>No recent alerts</li>"
    alive = st.get("heartbeat_alive")
    badge, color = ("ALIVE", "#0F766E") if alive else ("STALE", "#C2410C")
    nets = ", ".join(st.get("scan_subnets") or []) or "(not set)"
    src = st.get("heartbeat_source") or "?"
    return f"""<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><meta http-equiv=\"refresh\" content=\"30\"/><title>SENTINEL</title>
<style>body{{font-family:system-ui;margin:0;background:#0B1F3A;color:#E2E8F0}}header{{padding:1rem;background:#071525;border-bottom:3px solid #1A8CFF}}
.card{{background:#132337;border-radius:10px;padding:1rem;margin:1rem auto;max-width:900px}}.badge{{background:{color};padding:.2rem .6rem;border-radius:999px;font-weight:700}}
code{{color:#7DD3FC;font-size:.78rem}}</style></head><body>
<header><h1>SENTINEL</h1><div>TrinTech Digital Defense</div></header>
<div class=\"card\"><span class=\"badge\">{badge}</span>
<p>Host: {st.get(\"host\")} · HB: {st.get(\"heartbeat_age_seconds\")}s ({src})</p>
<p>Subnets: {nets} · Hygiene suppressed: {st.get(\"hygiene_suppressed\")}</p></div>
<div class=\"card\"><h3>Buckets</h3><table>{rows}</table></div>
<div class=\"card\"><h3>Recent</h3><ul>{recent}</ul></div>
</body></html>"""

def dashboard_write() -> dict:
    path = _data() / "dashboard.html"
    path.write_text(_html_page())
    return {"ok": True, "file": str(path)}

def dashboard_serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    dashboard_write(); heartbeat_write({"source": "dashboard"})
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            dashboard_write()
            body = _html_page().encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    httpd = HTTPServer((host, port), H)
    print(f"[+] dashboard http://{host}:{port}/")
    try: httpd.serve_forever()
    except KeyboardInterrupt: print("\n[+] stopped")

def phase5_self_check() -> dict:
    ensure_hygiene_defaults(); ensure_whatsapp_defaults()
    return {"auto_subnet": True, "heartbeat": True, "heartbeat_in_hunt": True, "digest": True, "whatsapp_digest": True, "alert_hygiene": True, "dashboard": True, "detected_subnets": detect_local_subnets(), "hygiene": hygiene_status(), "whatsapp_phone": ((_cfg().get("alerting") or {}).get("whatsapp") or {}).get("phone")}
