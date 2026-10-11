#!/usr/bin/env python3
"""FEATURE 16 — External posture drift monitor."""
from __future__ import annotations
import json
import os
import socket
import ssl
import subprocess
from datetime import datetime
from pathlib import Path

def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def history_path() -> Path:
    return _data() / "external_posture.json"

def _cfg() -> dict:
    p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _dig(name: str, rtype: str) -> str:
    try:
        r = subprocess.run(["dig", "+short", name, rtype], capture_output=True, text=True, timeout=10)
        return (r.stdout or "").strip()
    except Exception:
        return ""

def check_dns_email(domain: str) -> dict:
    spf = _dig(domain, "TXT")
    dmarc = _dig(f"_dmarc.{domain}", "TXT")
    return {"spf_present": "v=spf1" in spf.lower(), "dmarc_present": "v=dmarc1" in dmarc.lower(),
            "spf_raw": spf[:200], "dmarc_raw": dmarc[:200]}

def check_tls(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"ok": True, "not_after": cert.get("notAfter"), "host": host}
    except Exception as e:
        return {"ok": False, "error": str(e), "host": host}

def check_ports(host: str, ports=None) -> dict:
    ports = ports or [22, 80, 443, 8080, 3306]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return {"host": host, "open": open_ports}

def snapshot(domain: str = None, host: str = None) -> dict:
    cfg = _cfg()
    ext = cfg.get("external") or {}
    domain = domain or ext.get("domain") or ""
    host = host or ext.get("host") or domain or "127.0.0.1"
    return {"ts": datetime.now().isoformat(), "domain": domain, "host": host,
            "email": check_dns_email(domain) if domain else {},
            "tls": check_tls(host) if host and host != "127.0.0.1" else {"ok": None, "skipped": True},
            "ports": check_ports(host) if host else {}}

def check(domain: str = None, host: str = None) -> dict:
    snap = snapshot(domain, host)
    hist = []
    if history_path().exists():
        try:
            hist = json.loads(history_path().read_text())
            if not isinstance(hist, list):
                hist = []
        except Exception:
            hist = []
    events = []
    if hist:
        prev = hist[-1]
        pe, ce = prev.get("email") or {}, snap.get("email") or {}
        if pe.get("spf_present") and not ce.get("spf_present"):
            events.append({"type": "external", "reason": "external_posture", "severity": "HIGH",
                           "detail": "SPF record vanished", "ts": snap["ts"]})
        if pe.get("dmarc_present") and not ce.get("dmarc_present"):
            events.append({"type": "external", "reason": "external_posture", "severity": "HIGH",
                           "detail": "DMARC record vanished", "ts": snap["ts"]})
        po = set((prev.get("ports") or {}).get("open") or [])
        co = set((snap.get("ports") or {}).get("open") or [])
        if co - po:
            events.append({"type": "external", "reason": "external_posture", "severity": "MEDIUM",
                           "detail": f"New open ports: {sorted(co - po)}", "ts": snap["ts"]})
    hist.append(snap)
    history_path().write_text(json.dumps(hist[-60:], indent=2))
    return {"ok": True, "snapshot": snap, "events": events, "count": len(events)}
