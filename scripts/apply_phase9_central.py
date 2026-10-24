#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Inject /v1/cases routes into sentinel_central/server.py (Phase 9)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "sentinel_central" / "server.py"


def main() -> int:
    if not SERVER.exists():
        print(f"[!] missing {SERVER}")
        return 1
    text = SERVER.read_text(encoding="utf-8")
    original = text

    if "case_summaries" not in text:
        needle = 'con.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")'
        table = (
            needle
            + "\n    con.execute(\n"
            + '        "CREATE TABLE IF NOT EXISTS case_summaries ("\n'
            + '        "id INTEGER PRIMARY KEY AUTOINCREMENT,"\n'
            + '        "client_id TEXT NOT NULL,"\n'
            + '        "case_id TEXT NOT NULL,"\n'
            + '        "title TEXT,"\n'
            + '        "status TEXT,"\n'
            + '        "severity TEXT,"\n'
            + '        "assignee TEXT,"\n'
            + '        "updated_at TEXT,"\n'
            + '        "payload TEXT,"\n'
            + '        "UNIQUE(client_id, case_id))"\n'
            + "    )\n"
            + '    con.execute("CREATE INDEX IF NOT EXISTS idx_cases_client ON case_summaries(client_id)")'
        )
        if needle in text:
            text = text.replace(needle, table, 1)
            print("[+] case_summaries table")

    if "/v1/cases/sync" not in text:
        marker = (
            '            upsert_hb(client_id, body)\n'
            '            self._send(200, {"ok": True, "client_id": client_id})\n'
            "            return\n\n"
            '        self._send(404, {"error": "not found"})'
        )
        post = (
            '            upsert_hb(client_id, body)\n'
            '            self._send(200, {"ok": True, "client_id": client_id})\n'
            "            return\n\n"
            '        if u.path in ("/v1/cases/sync", "/api/cases/sync"):\n'
            '            items = body.get("cases") or body.get("items") or []\n'
            "            if not isinstance(items, list):\n"
            '                self._send(400, {"error": "cases must be a list"})\n'
            "                return\n"
            "            con = sqlite3.connect(DB)\n"
            "            n = 0\n"
            "            for it in items[:200]:\n"
            "                if not isinstance(it, dict):\n"
            "                    continue\n"
            '                cid = str(it.get("id") or it.get("case_id") or "").strip()\n'
            "                if not cid:\n"
            "                    continue\n"
            '                con.execute(\n'
            '                    "INSERT INTO case_summaries (client_id, case_id, title, status, severity, assignee, updated_at, payload) "\n'
            '                    "VALUES (?,?,?,?,?,?,?,?) "\n'
            '                    "ON CONFLICT(client_id, case_id) DO UPDATE SET "\n'
            '                    "title=excluded.title, status=excluded.status, severity=excluded.severity, "\n'
            '                    "assignee=excluded.assignee, updated_at=excluded.updated_at, payload=excluded.payload",\n'
            "                    (\n"
            "                        client_id,\n"
            "                        cid[:80],\n"
            '                        str(it.get("title") or "")[:300],\n'
            '                        str(it.get("status") or "")[:40],\n'
            '                        str(it.get("severity") or "")[:40],\n'
            '                        str(it.get("assignee") or "")[:80],\n'
            '                        str(it.get("updated_at") or _now())[:64],\n'
            "                        json.dumps(it)[:4000],\n"
            "                    ),\n"
            "                )\n"
            "                n += 1\n"
            "            con.commit()\n"
            "            con.close()\n"
            '            audit(client_id, "cases_sync", "ok", target_type="cases", detail=f"n={n}")\n'
            '            self._send(200, {"ok": True, "upserted": n})\n'
            "            return\n\n"
            '        self._send(404, {"error": "not found"})'
        )
        if marker in text:
            text = text.replace(marker, post, 1)
            print("[+] POST /v1/cases/sync")
        else:
            print("[!] POST marker not found")

    if 'u.path in ("/v1/cases"' not in text:
        get_block = (
            '        if u.path in ("/v1/cases", "/api/cases"):\n'
            '            if role != "master":\n'
            '                audit(actor, "list_cases", "denied", detail="agent key insufficient")\n'
            '                self._send(403, {"error": "master key required"})\n'
            "                return\n"
            "            qs = parse_qs(u.query)\n"
            '            client = (qs.get("client_id") or qs.get("client") or [""])[0]\n'
            '            limit = min(int((qs.get("limit") or ["100"])[0] or 100), 500)\n'
            "            con = sqlite3.connect(DB)\n"
            "            if client:\n"
            '                rows = con.execute(\n'
            '                    "SELECT client_id, case_id, title, status, severity, assignee, updated_at "\n'
            '                    "FROM case_summaries WHERE client_id=? ORDER BY updated_at DESC LIMIT ?",\n'
            "                    (client, limit),\n"
            "                ).fetchall()\n"
            "            else:\n"
            '                rows = con.execute(\n'
            '                    "SELECT client_id, case_id, title, status, severity, assignee, updated_at "\n'
            '                    "FROM case_summaries ORDER BY updated_at DESC LIMIT ?",\n'
            "                    (limit,),\n"
            "                ).fetchall()\n"
            "            con.close()\n"
            "            items = [\n"
            "                {\n"
            '                    "client_id": r[0],\n'
            '                    "case_id": r[1],\n'
            '                    "title": r[2],\n'
            '                    "status": r[3],\n'
            '                    "severity": r[4],\n'
            '                    "assignee": r[5],\n'
            '                    "updated_at": r[6],\n'
            "                }\n"
            "                for r in rows\n"
            "            ]\n"
            '            audit("master", "list_cases", "ok", detail=f"n={len(items)}")\n'
            '            self._send(200, {"cases": items})\n'
            "            return\n\n"
        )
        for marker in (
            '        self._send(404, {"error": "not found"})\n\n\ndef secrets_compare',
            '        self._send(404, {"error": "not found"})\n\ndef secrets_compare',
        ):
            if marker in text:
                text = text.replace(
                    marker,
                    get_block + '        self._send(404, {"error": "not found"})\n\n\ndef secrets_compare',
                    1,
                )
                print("[+] GET /v1/cases")
                break
        else:
            print("[!] GET marker not found")

    if text == original:
        print("[=] central already Phase 9 or markers moved")
        return 0
    SERVER.write_text(text, encoding="utf-8")
    print(f"[+] updated {SERVER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
