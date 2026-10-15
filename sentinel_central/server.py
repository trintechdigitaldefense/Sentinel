# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL central management server — per-agent API keys (MSP mode).

Run:
  python3 -m sentinel_central.server --port 8443 --master-key SECRET
  python3 -m sentinel_central.server --revoke AGENT_ID --master-key SECRET
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import ssl
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA = Path(os.environ.get("SENTINEL_CENTRAL_DIR", Path.home() / ".sentinel-central"))
DB = DATA / "central.db"
MASTER = os.environ.get("SENTINEL_MASTER_KEY", "")


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute(
        """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT, ts TEXT, severity TEXT, title TEXT, detail TEXT, payload TEXT
        )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS heartbeats (
        client_id TEXT PRIMARY KEY, last_seen TEXT, meta TEXT
        )"""
    )
    con.commit()
    con.close()


def insert_event(client_id: str, body: dict) -> None:
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO events (client_id, ts, severity, title, detail, payload) VALUES (?,?,?,?,?,?)",
        (
            client_id,
            body.get("ts") or datetime.now().isoformat(),
            body.get("severity") or "INFO",
            body.get("title") or "",
            body.get("detail") or "",
            json.dumps(body),
        ),
    )
    con.commit()
    con.close()


def upsert_hb(client_id: str, meta: dict) -> None:
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO heartbeats (client_id, last_seen, meta) VALUES (?,?,?) "
        "ON CONFLICT(client_id) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (client_id, datetime.now().isoformat(), json.dumps(meta or {})),
    )
    con.commit()
    con.close()


class Handler(BaseHTTPRequestHandler):
    master_key: str = ""

    def log_message(self, *a):
        pass

    def _read(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def _send(self, code: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth_agent(self) -> tuple[bool, str]:
        from modules.agent_keys import verify_key, list_agents
        key = self.headers.get("X-API-Key") or ""
        agent_id = self.headers.get("X-Client-Id") or ""
        if self.master_key and key == self.master_key:
            return True, agent_id or "master"
        if verify_key(agent_id, key):
            return True, agent_id
        # key-only scan
        if verify_key("", key):
            return True, agent_id or "unknown"
        return False, ""

    def do_POST(self):
        u = urlparse(self.path)
        body = self._read()
        key = self.headers.get("X-API-Key") or ""

        if u.path in ("/v1/enroll", "/api/enroll"):
            if key != self.master_key:
                self._send(401, {"error": "master key required for enroll"})
                return
            from modules.agent_keys import issue_key
            aid = body.get("agent_id") or ""
            resp = issue_key(aid, self.master_key, key)
            self._send(200 if resp.get("ok") else 400, resp)
            return

        ok, client_id = self._auth_agent()
        if not ok:
            self._send(401, {"error": "unauthorized or revoked"})
            return
        client_id = body.get("client_id") or client_id or "unknown"

        if u.path in ("/v1/events", "/api/events"):
            insert_event(client_id, body)
            self._send(200, {"ok": True})
            return
        if u.path in ("/v1/heartbeat", "/api/heartbeat"):
            upsert_hb(client_id, body)
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})

    def do_GET(self):
        ok, _ = self._auth_agent()
        if not ok:
            self._send(401, {"error": "unauthorized or revoked"})
            return
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path in ("/v1/clients", "/api/clients"):
            con = sqlite3.connect(DB)
            rows = con.execute("SELECT client_id, last_seen, meta FROM heartbeats").fetchall()
            con.close()
            from modules.agent_keys import list_agents
            clients = [{"client_id": r[0], "last_seen": r[1], "meta": json.loads(r[2] or "{}")} for r in rows]
            self._send(200, {"clients": clients, "agents": list_agents()})
            return
        if u.path in ("/v1/events", "/api/events"):
            client = (qs.get("client") or [None])[0]
            con = sqlite3.connect(DB)
            if client:
                rows = con.execute(
                    "SELECT client_id, ts, severity, title, detail FROM events WHERE client_id=? ORDER BY id DESC LIMIT 100",
                    (client,),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT client_id, ts, severity, title, detail FROM events ORDER BY id DESC LIMIT 100"
                ).fetchall()
            con.close()
            events = [
                {"client_id": r[0], "ts": r[1], "severity": r[2], "title": r[3], "detail": r[4]}
                for r in rows
            ]
            self._send(200, {"events": events})
            return
        self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="SENTINEL central server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--master-key", "--key", dest="master_key", default=os.environ.get("SENTINEL_MASTER_KEY", ""))
    ap.add_argument("--cert", default="")
    ap.add_argument("--keyfile", default="")
    ap.add_argument("--revoke", default="", help="Revoke agent_id and exit")
    args = ap.parse_args()
    if not args.master_key:
        print("[!] --master-key required")
        raise SystemExit(1)
    if args.revoke:
        from modules.agent_keys import revoke
        print(revoke(args.revoke, args.master_key, args.master_key))
        return
    init_db()
    Handler.master_key = args.master_key
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    if args.cert and args.keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"[+] SENTINEL central HTTPS on {args.host}:{args.port}")
    else:
        print(f"[+] SENTINEL central HTTP on {args.host}:{args.port} (use TLS in production)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
