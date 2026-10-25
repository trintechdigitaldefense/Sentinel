# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SIEM / centralized logging integration for SENTINEL alerts.

Supports:
  - syslog UDP/TCP (RFC 5424-ish)
  - CEF over syslog (ArcSight / many SIEMs)
  - Splunk HEC (HTTP Event Collector)
  - Generic HTTPS webhook (JSON)
  - Local JSONL ship file (for agents/filebeat)

Config under ~/.sentinel/config.json → alerting.siem
"""
from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.siem")

# CEF severity 0-10
_SEV = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 3,
    "INFO": 1,
}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _cfg() -> dict:
    p = _home() / "config.json"
    if not p.exists():
        return {}
    try:
        full = json.loads(p.read_text())
        return (full.get("alerting") or {}).get("siem") or {}
    except Exception:
        return {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_cef(
    severity: str,
    title: str,
    detail: str = "",
    meta: Optional[dict] = None,
    host: str = "",
) -> str:
    """Common Event Format for SIEM parsers."""
    meta = meta or {}
    host = host or socket.gethostname()
    sev = _SEV.get((severity or "INFO").upper(), 5)
    # Escape CEF extension special chars
    def esc(s: str) -> str:
        return (
            str(s)
            .replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", " ")
            .replace("\r", " ")[:500]
        )

    device_vendor = "TrinTech"
    device_product = "Sentinel"
    device_version = meta.get("version") or "3.9"
    signature = esc(title)[:64]
    name = esc(title)[:128]
    extensions = [
        f"msg={esc(detail)}",
        f"dhost={esc(host)}",
        f"cs1={esc(meta.get('type') or title)}",
        f"cs1Label=AlertType",
        f"rt={int(time.time() * 1000)}",
    ]
    if meta.get("ip"):
        extensions.append(f"src={esc(meta['ip'])}")
    return (
        f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature}|{name}|{sev}|"
        + " ".join(extensions)
    )


def to_json_event(
    severity: str,
    title: str,
    detail: str = "",
    meta: Optional[dict] = None,
) -> dict:
    return {
        "ts": _now(),
        "product": "sentinel",
        "vendor": "TrinTech Digital Defense",
        "severity": (severity or "INFO").upper(),
        "title": title,
        "detail": (detail or "")[:2000],
        "host": socket.gethostname(),
        "meta": meta or {},
    }


def send_syslog(
    message: str,
    host: str,
    port: int = 514,
    protocol: str = "udp",
    facility: int = 16,  # local0
    severity: int = 6,
) -> dict:
    """Send a single syslog line. protocol: udp|tcp."""
    pri = facility * 8 + severity
    hostname = socket.gethostname()
    line = f"<{pri}>1 {_now()} {hostname} sentinel - - - {message}\n"
    data = line.encode("utf-8", errors="replace")
    try:
        if protocol.lower() == "tcp":
            with socket.create_connection((host, int(port)), timeout=8) as s:
                s.sendall(data)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(data, (host, int(port)))
            s.close()
        return {"ok": True, "channel": "syslog", "host": host, "port": port, "proto": protocol}
    except Exception as e:
        return {"ok": False, "channel": "syslog", "error": str(e)}


def normalize_hec_url(url: str) -> str:
    """Ensure URL ends with /services/collector or /services/collector/event."""
    u = (url or "").strip().rstrip("/")
    if not u:
        return u
    if "/services/collector" not in u:
        u = u + "/services/collector"
    return u


def send_splunk_hec(
    event: dict,
    url: str,
    token: str,
    index: Optional[str] = None,
    source: str = "sentinel",
    sourcetype: str = "sentinel:alert",
    verify_tls: bool = True,
    timeout: int = 15,
) -> dict:
    """POST one event to Splunk HTTP Event Collector."""
    url = normalize_hec_url(url)
    if not url or not token:
        return {"ok": False, "channel": "splunk_hec", "error": "url and token required"}
    payload = {
        "time": time.time(),
        "host": socket.gethostname(),
        "source": source,
        "sourcetype": sourcetype,
        "event": event,
    }
    if index:
        payload["index"] = index
    body = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "User-Agent": "Sentinel-SplunkHEC/1.0",
        },
        method="POST",
    )
    ctx = None if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except Exception:
                parsed = {"raw": raw[:200]}
            code = int(getattr(resp, "status", 200) or 200)
            ok = code == 200 and (not parsed or parsed.get("code") in (0, None))
            return {
                "ok": ok,
                "channel": "splunk_hec",
                "status": code,
                "response": parsed,
                "url": url.split("?")[0],
            }
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            err_body = str(e)
        return {"ok": False, "channel": "splunk_hec", "error": f"HTTP {e.code}: {err_body}", "status": e.code}
    except Exception as e:
        return {"ok": False, "channel": "splunk_hec", "error": str(e)}


def send_splunk_hec_batch(
    events: list,
    url: str,
    token: str,
    index: Optional[str] = None,
    source: str = "sentinel",
    sourcetype: str = "sentinel:alert",
    verify_tls: bool = True,
) -> dict:
    """POST multiple events as NDJSON (Splunk HEC batch)."""
    url = normalize_hec_url(url)
    if not url or not token:
        return {"ok": False, "error": "url and token required"}
    lines = []
    for ev in events:
        payload = {
            "time": time.time(),
            "host": socket.gethostname(),
            "source": source,
            "sourcetype": sourcetype,
            "event": ev if isinstance(ev, dict) else {"message": str(ev)},
        }
        if index:
            payload["index"] = index
        lines.append(json.dumps(payload, default=str))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "User-Agent": "Sentinel-SplunkHEC/1.0",
        },
        method="POST",
    )
    ctx = None if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return {"ok": True, "channel": "splunk_hec_batch", "count": len(events), "status": getattr(resp, "status", 200)}
    except Exception as e:
        return {"ok": False, "channel": "splunk_hec_batch", "error": str(e), "count": len(events)}


def configure_splunk(
    url: str,
    token: str,
    index: str = "main",
    source: str = "sentinel",
    sourcetype: str = "sentinel:alert",
    verify_tls: bool = True,
    enable_siem: bool = True,
) -> dict:
    """Write Splunk HEC settings into ~/.sentinel/config.json and enable SIEM."""
    import json as _json
    p = _home() / "config.json"
    try:
        cfg = _json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        cfg = {}
    alerting = cfg.setdefault("alerting", {})
    siem = alerting.setdefault("siem", {})
    siem["enabled"] = bool(enable_siem)
    siem.setdefault("format", "json")
    siem.setdefault("min_severity", "LOW")
    siem["splunk_hec"] = {
        "enabled": True,
        "url": normalize_hec_url(url),
        "token": token,
        "index": index or "",
        "source": source,
        "sourcetype": sourcetype,
        "verify_tls": bool(verify_tls),
    }
    sf = siem.setdefault("ship_file", {"enabled": True, "path": ""})
    sf["enabled"] = True
    alerting["siem"] = siem
    cfg["alerting"] = alerting
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_json.dumps(cfg, indent=2))
    return {
        "ok": True,
        "path": str(p),
        "url": siem["splunk_hec"]["url"],
        "index": index,
        "sourcetype": sourcetype,
        "siem_enabled": True,
        "token_set": bool(token),
    }


def splunk_from_env() -> dict:
    """Configure Splunk from SPLUNK_HEC_URL + SPLUNK_HEC_TOKEN (+ optional INDEX)."""
    url = os.environ.get("SPLUNK_HEC_URL") or os.environ.get("SPLUNK_URL") or ""
    token = os.environ.get("SPLUNK_HEC_TOKEN") or os.environ.get("SPLUNK_TOKEN") or ""
    index = os.environ.get("SPLUNK_HEC_INDEX") or os.environ.get("SPLUNK_INDEX") or "main"
    verify = os.environ.get("SPLUNK_HEC_VERIFY", "1").lower() not in ("0", "false", "no")
    if not url or not token:
        return {
            "ok": False,
            "error": "Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN",
            "hint": "export SPLUNK_HEC_URL=https://splunk:8088 SPLUNK_HEC_TOKEN=xxxx",
        }
    return configure_splunk(url, token, index=index, verify_tls=verify)


def splunk_health() -> dict:
    """Ping configured HEC with a tiny health event (or report config status)."""
    cfg = _cfg()
    sp = cfg.get("splunk_hec") or {}
    if not sp.get("enabled"):
        return {"ok": False, "error": "splunk_hec not enabled — run: python3 sentinel.py siem splunk-configure ..."}
    url, token = sp.get("url") or "", sp.get("token") or ""
    if not url or not token:
        return {"ok": False, "error": "missing url or token in config"}
    event = to_json_event("INFO", "SPLUNK_HEC_HEALTH", "Sentinel Splunk HEC health check", {"type": "SPLUNK_HEC_HEALTH"})
    r = send_splunk_hec(
        event,
        url=url,
        token=token,
        index=sp.get("index") or None,
        source=sp.get("source") or "sentinel",
        sourcetype=sp.get("sourcetype") or "sentinel:alert",
        verify_tls=sp.get("verify_tls", True),
    )
    return {"ok": bool(r.get("ok")), "hec": r, "url": normalize_hec_url(url)}


def flush_ship_to_splunk(limit: int = 100) -> dict:
    """Replay recent ship_file lines to Splunk HEC (best-effort)."""
    cfg = _cfg()
    sp = cfg.get("splunk_hec") or {}
    if not sp.get("enabled") or not sp.get("url") or not sp.get("token"):
        return {"ok": False, "error": "splunk_hec not configured"}
    ship = Path((cfg.get("ship_file") or {}).get("path") or (_home() / "data" / "siem_ship.jsonl"))
    if not ship.exists():
        return {"ok": True, "sent": 0, "note": "no ship file"}
    events = []
    for ln in ship.read_text(errors="ignore").splitlines()[-limit:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except Exception:
            events.append({"message": ln[:500]})
    if not events:
        return {"ok": True, "sent": 0}
    r = send_splunk_hec_batch(
        events,
        url=sp["url"],
        token=sp["token"],
        index=sp.get("index") or None,
        source=sp.get("source") or "sentinel",
        sourcetype=sp.get("sourcetype") or "sentinel:alert",
        verify_tls=sp.get("verify_tls", True),
    )
    return r


def send_webhook(url: str, event: dict, headers: Optional[dict] = None, verify_tls: bool = True) -> dict:
    body = json.dumps(event).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "User-Agent": "Sentinel-SIEM/1.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    ctx = None if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return {"ok": True, "channel": "siem_webhook", "status": getattr(resp, "status", 200)}
    except Exception as e:
        return {"ok": False, "channel": "siem_webhook", "error": str(e)}


def append_ship_file(event: dict, path: Optional[str] = None) -> dict:
    """Append JSONL for Filebeat / SIEM agents to ship."""
    p = Path(path) if path else (_home() / "data" / "siem_ship.jsonl")
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(p, "a") as f:
            f.write(json.dumps(event, default=str) + "\n")
        return {"ok": True, "channel": "ship_file", "path": str(p)}
    except Exception as e:
        return {"ok": False, "channel": "ship_file", "error": str(e)}


def emit(
    severity: str,
    title: str,
    detail: str = "",
    meta: Optional[dict] = None,
    cfg: Optional[dict] = None,
) -> dict:
    """Fan-out alert to all enabled SIEM channels from config."""
    cfg = cfg if cfg is not None else _cfg()
    result = {"ok": True, "sent": False, "channels": []}
    if not cfg.get("enabled"):
        result["skipped"] = True
        result["reason"] = "siem disabled"
        return result

    # min severity filter
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = (cfg.get("min_severity") or "LOW").upper()
    sev = (severity or "INFO").upper()
    try:
        if order.index(sev) < order.index(min_sev if min_sev in order else "LOW"):
            return {"ok": True, "skipped": True, "reason": f"below {min_sev}"}
    except ValueError:
        pass

    event = to_json_event(sev, title, detail, meta)
    fmt = (cfg.get("format") or "json").lower()

    # Syslog
    sy = cfg.get("syslog") or {}
    if sy.get("enabled") and sy.get("host"):
        if fmt == "cef":
            msg = to_cef(sev, title, detail, meta)
        else:
            msg = json.dumps(event, default=str)
        pri_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 5, "LOW": 6, "INFO": 6}
        r = send_syslog(
            msg,
            host=sy["host"],
            port=int(sy.get("port") or 514),
            protocol=sy.get("protocol") or "udp",
            severity=pri_map.get(sev, 6),
        )
        result["channels"].append(r)
        if r.get("ok"):
            result["sent"] = True

    # Splunk HEC
    sp = cfg.get("splunk_hec") or {}
    if sp.get("enabled") and sp.get("url") and sp.get("token"):
        r = send_splunk_hec(
            event,
            url=sp["url"],
            token=sp["token"],
            index=sp.get("index"),
            source=sp.get("source") or "sentinel",
            sourcetype=sp.get("sourcetype") or "sentinel:alert",
            verify_tls=sp.get("verify_tls", True),
        )
        result["channels"].append(r)
        if r.get("ok"):
            result["sent"] = True

    # Generic SIEM webhook
    wh = cfg.get("webhook") or {}
    if wh.get("enabled") and wh.get("url"):
        r = send_webhook(wh["url"], event, headers=wh.get("headers"), verify_tls=wh.get("verify_tls", True))
        result["channels"].append(r)
        if r.get("ok"):
            result["sent"] = True

    # Ship file for agents
    sf = cfg.get("ship_file") or {}
    if sf.get("enabled", True):  # default on when siem.enabled — local buffer
        r = append_ship_file(event, path=sf.get("path"))
        result["channels"].append(r)
        if r.get("ok"):
            result["sent"] = True

    result["ok"] = result["sent"] or not any(
        (not c.get("ok") and not c.get("skipped")) for c in result["channels"]
    )
    return result


def status() -> dict:
    cfg = _cfg()
    ship = _home() / "data" / "siem_ship.jsonl"
    n = 0
    if ship.exists():
        n = sum(1 for ln in ship.read_text().splitlines() if ln.strip())
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled")),
        "format": cfg.get("format") or "json",
        "min_severity": cfg.get("min_severity") or "LOW",
        "syslog": bool((cfg.get("syslog") or {}).get("enabled")),
        "splunk_hec": bool((cfg.get("splunk_hec") or {}).get("enabled")),
        "webhook": bool((cfg.get("webhook") or {}).get("enabled")),
        "ship_file_lines": n,
        "ship_file": str(ship),
        "config_keys": list(cfg.keys()),
    }


def test_emit() -> dict:
    return emit(
        "MEDIUM",
        "SIEM_TEST",
        detail="Sentinel SIEM connectivity test",
        meta={"type": "SIEM_TEST"},
    )



def enable_defaults(enable: bool = True) -> dict:
    """Ensure alerting.siem block exists and optionally enable ship_file + flag."""
    import json
    p = _home() / "config.json"
    try:
        cfg = json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        cfg = {}
    alerting = cfg.setdefault("alerting", {})
    siem = alerting.setdefault("siem", {})
    siem["enabled"] = bool(enable)
    siem.setdefault("format", "json")
    siem.setdefault("min_severity", "LOW")
    siem.setdefault("syslog", {"enabled": False, "host": "", "port": 514, "protocol": "udp"})
    siem.setdefault("splunk_hec", {"enabled": False, "url": "", "token": "", "verify_tls": True})
    siem.setdefault("webhook", {"enabled": False, "url": "", "verify_tls": True})
    sf = siem.setdefault("ship_file", {"enabled": True, "path": ""})
    sf["enabled"] = True
    alerting["siem"] = siem
    cfg["alerting"] = alerting
    # dashboard defaults
    dash = cfg.setdefault("dashboard", {})
    if not dash.get("token"):
        import secrets
        dash["token"] = secrets.token_urlsafe(24)
    dash.setdefault("port", 8792)
    dash.setdefault("allow_control", True)
    cfg["dashboard"] = dash
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))
    return {"ok": True, "siem_enabled": siem["enabled"], "path": str(p), "dashboard_port": dash.get("port")}
