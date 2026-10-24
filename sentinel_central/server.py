# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL central management server — Phase 5 hardened (MSP mode).

Hardening goals:
- Stronger agent isolation (client_id always from verified agent, never from body)
- Audit trail for enroll, revoke, auth failures, sensitive reads
- Fail-closed authorization
- Master key only for admin actions (enroll / revoke / list), not for agent data paths

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
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA = Path(os.environ.get("SENTINEL_CENTRAL_DIR", Path.home() / ".sentinel-central"))
DB = DATA / "central.db"
MASTER = os.environ.get("SENTINEL_MASTER_KEY", "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute(
        """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
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
    con.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,
        result TEXT NOT NULL,
        detail TEXT
        )"""
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")
    con.commit()
    con.close()


def audit(
    actor: str,
    action: str,
    result: str,
    target_type: str = "",
    target_id: str = "",
    detail: str = "",
) -> None:
    """Append an immutable audit record. Never stores secrets."""
    try:
        con = sqlite3.connect(DB)
        con.execute(
            "INSERT INTO audit_events (ts, actor, action, target_type, target_id, result, detail) "
            "VALUES (?,?,?,?,?,?,?)",
            (_now(), actor or "unknown", action, target_type or "", target_id or "", result, detail or ""),
        )
        con.commit()
        con.close()
    except Exception:
        # Audit must not break the main path; failures are silent by design.
        pass


def insert_event(client_id: str, body: dict) -> None:
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO events (client_id, ts, severity, title, detail, payload) VALUES (?,?,?,?,?,?)",
        (
            client_id,
            body.get("ts") or _now(),
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
        (client_id, _now(), json.dumps(meta or {})),
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
        if n > 1_048_576:  # 1 MiB hard limit
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
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _auth_agent(self) -> tuple[bool, str, str]:
        """Return (ok, agent_id, role).

        role is 'master' or 'agent'.
        Master key is accepted only for admin endpoints; agent data paths require a valid agent key.
        client_id is always derived from the verified agent record — never from the request body.
        """
        from modules.agent_keys import verify_key, resolve_agent_id

        key = self.headers.get("X-API-Key") or ""
        header_agent = (self.headers.get("X-Client-Id") or "").strip()

        if self.master_key and key and secrets_compare(self.master_key, key):
            return True, header_agent or "master", "master"

        # Prefer explicit agent_id + key
        if header_agent and verify_key(header_agent, key):
            return True, header_agent, "agent"

        # Key-only lookup (agent_id recovered from hash)
        resolved = resolve_agent_id(key)
        if resolved:
            return True, resolved, "agent"

        return False, "", ""

    def do_POST(self):
        u = urlparse(self.path)
        body = self._read()
        key = self.headers.get("X-API-Key") or ""

        # --- Admin: enroll (master key only) ---
        if u.path in ("/v1/enroll", "/api/enroll"):
            if not self.master_key or not secrets_compare(self.master_key, key):
                audit("anonymous", "enroll", "denied", detail="missing or invalid master key")
                self._send(401, {"error": "master key required for enroll"})
                return
            from modules.agent_keys import issue_key

            aid = (body.get("agent_id") or "").strip()
            resp = issue_key(aid, self.master_key, key)
            if resp.get("ok"):
                audit("master", "enroll", "ok", target_type="agent", target_id=resp.get("agent_id", ""))
            else:
                audit("master", "enroll", "fail", detail=resp.get("error", ""))
            self._send(200 if resp.get("ok") else 400, resp)
            return

        ok, client_id, role = self._auth_agent()
        if not ok:
            audit("anonymous", "auth", "denied", detail=f"path={u.path}")
            self._send(401, {"error": "unauthorized or revoked"})
            return

        # Agent data paths: never trust body client_id
        if role != "agent":
            # Master key must not post events/heartbeats as if it were an agent
            audit(client_id or "master", "auth", "denied", detail="master key not allowed on agent data path")
            self._send(403, {"error": "agent key required for this endpoint"})
            return

        if u.path in ("/v1/events", "/api/events"):
            insert_event(client_id, body)
            audit(client_id, "event_ingest", "ok", target_type="event")
            self._send(200, {"ok": True, "client_id": client_id})
            return

        if u.path in ("/v1/heartbeat", "/api/heartbeat"):
            upsert_hb(client_id, body)
            self._send(200, {"ok": True, "client_id": client_id})
            return

        self._send(404, {"error": "not found"})

    def do_GET(self):
        ok, actor, role = self._auth_agent()
        if not ok:
            audit("anonymous", "auth", "denied", detail=f"GET {self.path}")
            self._send(401, {"error": "unauthorized or revoked"})
            return

        u = urlparse(self.path)
        qs = parse_qs(u.query)

        # Admin list endpoints require master role
        if u.path in ("/v1/clients", "/api/clients"):
            if role != "master":
                audit(actor, "list_clients", "denied", detail="agent key insufficient")
                self._send(403, {"error": "master key required"})
                return
            con = sqlite3.connect(DB)
            rows = con.execute("SELECT client_id, last_seen, meta FROM heartbeats").fetchall()
            con.close()
            from modules.agent_keys import list_agents

            clients = [
                {"client_id": r[0], "last_seen": r[1], "meta": json.loads(r[2] or "{}")}
                for r in rows
            ]
            audit("master", "list_clients", "ok")
            self._send(200, {"clients": clients, "agents": list_agents()})
            return

        if u.path in ("/v1/events", "/api/events"):
            client = (qs.get("client") or [None])[0]
            con = sqlite3.connect(DB)
            if role == "agent":
                # Agents may only read their own events
                rows = con.execute(
                    "SELECT client_id, ts, severity, title, detail FROM events "
                    "WHERE client_id=? ORDER BY id DESC LIMIT 100",
                    (actor,),
                ).fetchall()
            elif client:
                rows = con.execute(
                    "SELECT client_id, ts, severity, title, detail FROM events "
                    "WHERE client_id=? ORDER BY id DESC LIMIT 100",
                    (client,),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT client_id, ts, severity, title, detail FROM events "
                    "ORDER BY id DESC LIMIT 100"
                ).fetchall()
            con.close()
            events = [
                {"client_id": r[0], "ts": r[1], "severity": r[2], "title": r[3], "detail": r[4]}
                for r in rows
            ]
            audit(actor, "list_events", "ok", target_id=client or actor)
            self._send(200, {"events": events})
            return

        if u.path in ("/v1/audit", "/api/audit"):
            if role != "master":
                audit(actor, "list_audit", "denied")
                self._send(403, {"error": "master key required"})
                return
            limit = min(int((qs.get("limit") or ["50"])[0] or 50), 500)
            con = sqlite3.connect(DB)
            rows = con.execute(
                "SELECT ts, actor, action, target_type, target_id, result, detail "
                "FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            con.close()
            records = [
                {
                    "ts": r[0],
                    "actor": r[1],
                    "action": r[2],
                    "target_type": r[3],
                    "target_id": r[4],
                    "result": r[5],
                    "detail": r[6],
                }
                for r in rows
            ]
            self._send(200, {"audit": records})
            return

        self._send(404, {"error": "not found"})


def secrets_compare(a: str, b: str) -> bool:
    import secrets

    if not a or not b:
        return False
    return secrets.compare_digest(a, b)


def main():
    ap = argparse.ArgumentParser(description="SENTINEL central server (Phase 5 hardened)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument(
        "--master-key",
        "--key",
        dest="master_key",
        default=os.environ.get("SENTINEL_MASTER_KEY", ""),
    )
    ap.add_argument("--cert", default="")
    ap.add_argument("--keyfile", default="")
    ap.add_argument("--revoke", default="", help="Revoke agent_id and exit")
    args = ap.parse_args()
    if not args.master_key:
        print("[!] --master-key required")
        raise SystemExit(1)

    init_db()

    if args.revoke:
        from modules.agent_keys import revoke

        result = revoke(args.revoke, args.master_key, args.master_key)
        if result.get("ok"):
            audit("master", "revoke", "ok", target_type="agent", target_id=args.revoke)
        else:
            audit("master", "revoke", "fail", target_type="agent", target_id=args.revoke, detail=result.get("error", ""))
        print(result)
        return

    Handler.master_key = args.master_key
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    if args.cert and args.keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"[+] SENTINEL central HTTPS on {args.host}:{args.port} (Phase 5)")
    else:
        print(f"[+] SENTINEL central HTTP on {args.host}:{args.port} (use TLS in production) — Phase 5")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
