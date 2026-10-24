#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Inject /v1/cases and /v1/cases/sync into sentinel_central/server.py."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "sentinel_central" / "server.py"

TABLE = """
    con.execute(
        \"\"\"CREATE TABLE IF NOT EXISTS case_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        title TEXT,
        status TEXT,
        severity TEXT,
        assignee TEXT,
        updated_at TEXT,
        payload TEXT,
        UNIQUE(client_id, case_id)
        )\"\"\"
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_cases_client ON case_summaries(client_id)")
"""

POST = """
        if u.path in (\"/v1/cases/sync\", \"/api/cases/sync\"):
            items = body.get(\"cases\") or body.get(\"items\") or []
            if not isinstance(items, list):
                self._send(400, {\"error\": \"cases must be a list\"})
                return
            con = sqlite3.connect(DB)
            n = 0
            for it in items[:200]:
                if not isinstance(it, dict):
                    continue
                cid = str(it.get(\"id\") or it.get(\"case_id\") or \"\").strip()
                if not cid:
                    continue
                con.execute(
                    \"INSERT INTO case_summaries (client_id, case_id, title, status, severity, assignee, updated_at, payload) \"
                    \"VALUES (?,?,?,?,?,?,?,?) \"
                    \"ON CONFLICT(client_id, case_id) DO UPDATE SET \"
                    \"title=excluded.title, status=excluded.status, severity=excluded.severity, \"
                    \"assignee=excluded.assignee, updated_at=excluded.updated_at, payload=excluded.payload\",
                    (
                        client_id,
                        cid[:80],
                        str(it.get(\"title\") or \"\")[:300],
                        str(it.get(\"status\") or \"\")[:40],
                        str(it.get(\"severity\") or \"\")[:40],
                        str(it.get(\"assignee\") or \"\")[:80],
                        str(it.get(\"updated_at\") or _now())[:64],
                        json.dumps(it)[:4000],
                    ),
                )
                n += 1
            con.commit()
            con.close()
            audit(client_id, \"cases_sync\", \"ok\", target_type=\"cases\", detail=f\"n={n}\")
            self._send(200, {\"ok\": True, \"upserted\": n})
            return
"""

# NOTE: script content continues in file on disk; use simplified loader below
"""
