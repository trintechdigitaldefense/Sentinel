# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Hardened multi-host central agent API.

Strengthened listener used by `sentinel central`:
- Constant-time token compare (Bearer or X-Sentinel-Token)
- Body size limit and basic rate limiting per source IP
- Threading server with SO_REUSEADDR
- Per-host latest snapshot + audit log of check-ins
- Stale-agent detection helper
- Fleet + canary registration on every report
- Structured JSON responses
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import socketserver
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("sentinel.central_agent")

DEFAULT_PORT = 8743
MAX_BODY = 512_000  # 512 KB
RATE_WINDOW_SEC = 60
RATE_MAX_PER_WINDOW = 120  # reports/min/IP


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def agents_dir() -> Path:
    d = _data() / "agents"
    d.mkdir(parents=True, exist_ok=True)
    return d


def audit_path() -> Path:
    return _data() / "central_audit.jsonl"


def _cfg() -> dict:
    p = _home() / "config.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def expected_token() -> str:
    try:
        from modules.remote_agent import ensure_agent_token
        return ensure_agent_token()
    except Exception:
        return str((_cfg().get("agent") or {}).get("shared_token") or "")


def audit(event: str, detail: dict) -> None:
    try:
        row = {"ts": datetime.now().isoformat(), "event": event, **detail}
        with open(audit_path(), "a") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except Exception:
        log.exception("audit write")


# Simple in-memory rate table
_rate_lock = threading.Lock()
_rate: dict[str, list[float]] = {}


def rate_allow(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = _rate.setdefault(ip, [])
        bucket[:] = [t for t in bucket if now - t < RATE_WINDOW_SEC]
        if len(bucket) >= RATE_MAX_PER_WINDOW:
            return False
        bucket.append(now)
        return True


def list_stale_agents(max_age_minutes: int = 15) -> dict:
    """Agents whose last_seen is older than max_age_minutes."""
    try:
        from modules.remote_agent import load_agents
        db = load_agents()
    except Exception:
        db = {"agents": {}}
    cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
    stale = []
    live = []
    for key, ent in (db.get("agents") or {}).items():
        ts = ent.get("last_seen")
        try:
            when = datetime.fromisoformat(str(ts))
        except Exception:
            stale.append({"key": key, **ent, "reason": "bad_ts"})
            continue
        if when < cutoff:
            stale.append({"key": key, "last_seen": ts, "hostname": ent.get("hostname"), "ip": ent.get("ip")})
        else:
            live.append({"key": key, "last_seen": ts, "hostname": ent.get("hostname"), "ip": ent.get("ip")})
    return {
        "ok": True,
        "max_age_minutes": max_age_minutes,
        "live": len(live),
        "stale": len(stale),
        "stale_agents": stale,
        "live_agents": live,
    }


def central_status_summary() -> dict:
    try:
        from modules.remote_agent import list_remote_agents
        from modules.network_fleet import fleet_status
        agents = list_remote_agents()
        fleet = fleet_status()
        stale = list_stale_agents()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "ts": datetime.now().isoformat(),
        "agents": agents.get("count", 0),
        "fleet_hosts": fleet.get("count", 0),
        "canary_planted": fleet.get("canary_planted", 0),
        "canary_pending_agent": fleet.get("canary_pending_agent", 0),
        "pending_review": fleet.get("pending_review", 0),
        "stale_agents": stale.get("stale", 0),
        "live_agents": stale.get("live", 0),
    }


class CentralAgentHandler(BaseHTTPRequestHandler):
    """Threaded central API handler."""

    send_alert_fn: Optional[Callable] = None
    canary_beacon_fn: Optional[Callable] = None

    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _token_ok(self) -> bool:
        """Accept shared token OR a valid per-agent API key (MSP mode)."""
        expected = expected_token()
        received = (self.headers.get("X-Sentinel-Token") or "").strip()
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            received = received or auth[7:].strip()
        agent_key = (self.headers.get("X-Agent-Key") or "").strip()
        key = received or agent_key
        if not key:
            return False
        if expected and secrets.compare_digest(str(key), str(expected)):
            return True
        try:
            from modules.agent_keys import resolve_agent_id, verify_key
            aid = resolve_agent_id(key)
            if aid:
                self._agent_id_resolved = aid  # type: ignore[attr-defined]
                return True
            hdr_id = (self.headers.get("X-Agent-Id") or "").strip()
            if hdr_id and verify_key(hdr_id, key):
                self._agent_id_resolved = hdr_id  # type: ignore[attr-defined]
                return True
        except Exception:
            log.exception("agent key verify")
        return False


    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, default=str).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Sentinel-Central", "3.16.2")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path.startswith("/canary/beacon") or path == "/canary/beacon":
            qs = parse_qs(parsed.query)
            cid = (qs.get("id") or [""])[0]
            meta = {"client": self._client_ip(), "path": self.path}
            try:
                if self.canary_beacon_fn:
                    self.canary_beacon_fn(cid, meta)
            except Exception:
                log.exception("canary beacon")
            self._json(200, {"status": "recorded", "id": cid})
            return

        if path in ("/health", "/agent/health"):
            self._json(200, {
                "ok": True,
                "service": "sentinel-central",
                "host": socket.gethostname(),
                "ts": datetime.now().isoformat(),
                "version": "3.16.2",
            })
            return

        if not self._token_ok():
            audit("auth_fail", {"ip": self._client_ip(), "path": path})
            self._json(401, {"error": "unauthorized"})
            return

        if path in ("/agents", "/agent/list", "/api/agents"):
            try:
                from modules.remote_agent import list_remote_agents
                self._json(200, list_remote_agents())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return

        if path in ("/fleet", "/api/fleet"):
            try:
                from modules.network_fleet import fleet_status
                self._json(200, fleet_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return

        if path in ("/agent/stale", "/stale"):
            qs = parse_qs(parsed.query)
            mins = 15
            try:
                mins = int((qs.get("minutes") or ["15"])[0])
            except Exception:
                mins = 15
            self._json(200, list_stale_agents(max_age_minutes=mins))
            return

        if path in ("/agent/status", "/status", "/api/status"):
            self._json(200, central_status_summary())
            return

        self._json(404, {"error": "not found", "path": path})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        ip = self._client_ip()

        if path not in ("/agent/report", "/api/agent/report"):
            self._json(404, {"error": "not found"})
            return

        if not self._token_ok():
            audit("auth_fail", {"ip": ip, "path": path})
            self._json(401, {"error": "unauthorized"})
            return

        if not rate_allow(ip):
            audit("rate_limited", {"ip": ip})
            self._json(429, {"error": "rate_limited", "window_sec": RATE_WINDOW_SEC})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length > MAX_BODY:
            self._json(413, {"error": "payload_too_large", "max": MAX_BODY})
            return

        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(body.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                data = {"payload": data}
        except Exception as e:
            self._json(400, {"error": f"invalid_json: {e}"})
            return

        if not data.get("ip"):
            data["ip"] = ip

        host_raw = str(data.get("hostname") or data.get("host") or "unknown")
        host = re.sub(r"[^a-zA-Z0-9_-]", "_", host_raw)[:40]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        adir = agents_dir()
        fname = adir / f"{host}_{ts}.json"
        latest = adir / f"{host}_latest.json"
        try:
            fname.write_text(json.dumps(data, indent=2, default=str))
            latest.write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            log.exception("save agent report")

        reg: dict[str, Any] = {"ok": False}
        try:
            from modules.remote_agent import register_agent_checkin
            reg = register_agent_checkin(data)
        except Exception as e:
            log.exception("register_agent_checkin")
            reg = {"ok": False, "error": str(e)}

        # Alert hooks
        sa = self.send_alert_fn
        for fpath, meta in (data.get("canaries") or {}).items():
            if isinstance(meta, dict) and meta.get("status") == "missing" and sa:
                try:
                    sa("AGENT_CANARY_MISSING", {
                        "agent": host_raw,
                        "ip": data.get("ip"),
                        "path": fpath,
                        "canary_id": meta.get("canary_id"),
                    })
                except Exception as e:
                    logging.getLogger('sentinel').debug('%s: %s', __name__, e)

        for proc in data.get("processes") or []:
            if isinstance(proc, dict) and proc.get("reason") == "reverse_shell" and sa:
                try:
                    sa("AGENT_REVERSE_SHELL", {
                        "agent": host_raw,
                        "ip": data.get("ip"),
                        "cmd": proc.get("cmd"),
                    })
                except Exception as e:
                    logging.getLogger('sentinel').debug('%s: %s', __name__, e)


        audit("agent_report", {
            "ip": ip,
            "hostname": host_raw,
            "canary_count": reg.get("canary_count", 0),
            "registered": reg.get("ok", False),
        })

        self._json(200, {
            "status": "ok",
            "registered": reg.get("ok", False),
            "canary_count": reg.get("canary_count", 0),
            "saved": fname.name,
            "latest": latest.name,
        })


class _ThreadedCentralServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _maybe_ssl(httpd: ThreadingHTTPServer) -> ThreadingHTTPServer:
    """Optional TLS if agent.tls_cert + agent.tls_key set in config."""
    try:
        cfg = _cfg().get("agent") or {}
        cert = cfg.get("tls_cert") or ""
        key = cfg.get("tls_key") or ""
        if cert and key and Path(cert).is_file() and Path(key).is_file():
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert, keyfile=key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            log.info("Central TLS enabled")
    except Exception:
        log.exception("TLS setup failed — continuing plain HTTP")
    return httpd


def start_central(
    port: Optional[int] = None,
    logger: Any = None,
    send_alert_fn: Optional[Callable] = None,
    canary_beacon_fn: Optional[Callable] = None,
) -> socketserver.TCPServer:
    """Start hardened central listener; returns server instance."""
    cfg = _cfg()
    port = int(port or (cfg.get("agent") or {}).get("port") or DEFAULT_PORT)
    agents_dir()
    tok = expected_token()
    if logger:
        logger.info("Central token ready (%s chars)", len(tok))

    def _beacon(cid, meta):
        if canary_beacon_fn:
            canary_beacon_fn(cid, meta)

    # Bind callbacks on class for handler instances
    CentralAgentHandler.send_alert_fn = send_alert_fn
    CentralAgentHandler.canary_beacon_fn = _beacon

    try:
        server = _ThreadedCentralServer(("0.0.0.0", port), CentralAgentHandler)
    except OSError as e:
        if logger:
            logger.error("Central bind failed on %s: %s", port, e)
        raise

    t = threading.Thread(target=server.serve_forever, daemon=True, name="sentinel-central")
    t.start()
    if logger:
        logger.info(
            "Central agent listener on port %s "
            "(report=/agent/report health=/health agents=/agents fleet=/fleet stale=/agent/stale)",
            port,
        )
    audit("central_start", {"port": port, "host": socket.gethostname()})
    return server
