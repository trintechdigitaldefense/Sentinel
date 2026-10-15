"""HTTPS-capable agent event collector + multi-client SQLite store (feature 10).

Run: python3 -m sentinel_central.server --port 8443 --key SECRET
Agents POST /v1/events with header X-API-Key.
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


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute(
        """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT,
        ts TEXT,
        severity TEXT,
        title TEXT,
        detail TEXT,
        payload TEXT
        )"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS heartbeats (
        client_id TEXT PRIMARY KEY,
        last_seen TEXT,
        meta TEXT
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
    api_key: str = ""

    def log_message(self, *a):
        pass

    def _auth(self) -> bool:
        return (self.headers.get("X-API-Key") or "") == self.api_key

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

    def do_POST(self):
        if not self._auth():
            self._send(401, {"error": "unauthorized"})
            return
        u = urlparse(self.path)
        body = self._read()
        client_id = body.get("client_id") or self.headers.get("X-Client-Id") or "unknown"
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
        if not self._auth():
            self._send(401, {"error": "unauthorized"})
            return
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path in ("/v1/clients", "/api/clients"):
            con = sqlite3.connect(DB)
            rows = con.execute("SELECT client_id, last_seen, meta FROM heartbeats").fetchall()
            con.close()
            clients = [{"client_id": r[0], "last_seen": r[1], "meta": json.loads(r[2] or "{}")} for r in rows]
            self._send(200, {"clients": clients})
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
    ap.add_argument("--key", required=True, help="Shared API key")
    ap.add_argument("--cert", default="", help="TLS cert path (optional)")
    ap.add_argument("--keyfile", default="", help="TLS key path (optional)")
    args = ap.parse_args()
    init_db()
    Handler.api_key = args.key
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
