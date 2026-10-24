# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Phase 7 — durable cases, triage, notes, assignment, evidence export.

Storage: ~/.sentinel/data/cases.db (SQLite)
Audit: every create / status / assign / note / evidence action is recorded.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

STATUSES = ("new", "triaging", "investigating", "contained", "resolved", "false_positive")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _db_path() -> Path:
    return _home() / "data" / "cases.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p))
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            severity TEXT NOT NULL DEFAULT 'medium',
            assignee TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            source_event_id TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT,
            summary TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS case_alerts (
            case_id TEXT NOT NULL,
            alert_ref TEXT NOT NULL,
            attached_at TEXT NOT NULL,
            PRIMARY KEY(case_id, alert_ref)
        );
        CREATE TABLE IF NOT EXISTS case_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
        CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id);
        CREATE INDEX IF NOT EXISTS idx_audit_case ON case_audit(case_id);
        """
    )
    con.commit()
    con.close()


def _audit(con: sqlite3.Connection, case_id: str, actor: str, action: str, detail: str = "") -> None:
    con.execute(
        "INSERT INTO case_audit (case_id, ts, actor, action, detail) VALUES (?,?,?,?,?)",
        (case_id, _now(), actor or "operator", action, detail or ""),
    )


def _new_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"CASE-{ts}-{secrets.token_hex(3).upper()}"


def create_case(
    title: str,
    severity: str = "medium",
    source: str = "",
    source_event_id: str = "",
    assignee: str = "",
    summary: str = "",
    actor: str = "operator",
    alert_refs: Optional[list[str]] = None,
) -> dict:
    init_db()
    title = (title or "").strip()
    if not title:
        return {"ok": False, "error": "title required"}
    severity = (severity or "medium").lower()
    if severity not in ("informational", "low", "medium", "high", "critical"):
        severity = "medium"
    cid = _new_id()
    now = _now()
    con = _connect()
    con.execute(
        "INSERT INTO cases (id, title, status, severity, assignee, source, source_event_id, "
        "created_at, updated_at, summary) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (cid, title[:300], "new", severity, assignee or "", source or "", source_event_id or "", now, now, summary or ""),
    )
    for ref in alert_refs or []:
        if ref:
            con.execute(
                "INSERT OR IGNORE INTO case_alerts (case_id, alert_ref, attached_at) VALUES (?,?,?)",
                (cid, str(ref)[:200], now),
            )
    _audit(con, cid, actor, "create", f"severity={severity}")
    con.commit()
    con.close()
    return {"ok": True, "case": get_case(cid)}


def get_case(case_id: str) -> Optional[dict]:
    init_db()
    con = _connect()
    row = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        con.close()
        return None
    notes = con.execute(
        "SELECT id, author, body, created_at FROM case_notes WHERE case_id=? ORDER BY id",
        (case_id,),
    ).fetchall()
    alerts = con.execute(
        "SELECT alert_ref, attached_at FROM case_alerts WHERE case_id=?",
        (case_id,),
    ).fetchall()
    audit = con.execute(
        "SELECT ts, actor, action, detail FROM case_audit WHERE case_id=? ORDER BY id",
        (case_id,),
    ).fetchall()
    con.close()
    return {
        "id": row["id"],
        "title": row["title"],
        "status": row["status"],
        "severity": row["severity"],
        "assignee": row["assignee"],
        "source": row["source"],
        "source_event_id": row["source_event_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "closed_at": row["closed_at"],
        "summary": row["summary"],
        "notes": [dict(n) for n in notes],
        "alert_refs": [{"ref": a["alert_ref"], "attached_at": a["attached_at"]} for a in alerts],
        "audit": [dict(a) for a in audit],
    }


def list_cases(
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    init_db()
    limit = max(1, min(int(limit or 50), 500))
    con = _connect()
    q = "SELECT id, title, status, severity, assignee, source, created_at, updated_at FROM cases"
    params: list[Any] = []
    clauses = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if assignee:
        clauses.append("assignee=?")
        params.append(assignee)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    rows = con.execute(q, params).fetchall()
    con.close()
    return [dict(r) for r in rows]


def set_status(case_id: str, status: str, actor: str = "operator") -> dict:
    init_db()
    status = (status or "").strip().lower()
    if status not in STATUSES:
        return {"ok": False, "error": f"invalid status; allowed: {', '.join(STATUSES)}"}
    con = _connect()
    row = con.execute("SELECT id, status FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        con.close()
        return {"ok": False, "error": "case not found"}
    closed = _now() if status in ("resolved", "false_positive") else None
    con.execute(
        "UPDATE cases SET status=?, updated_at=?, closed_at=COALESCE(?, closed_at) WHERE id=?",
        (status, _now(), closed, case_id),
    )
    _audit(con, case_id, actor, "status_change", f"{row['status']} -> {status}")
    con.commit()
    con.close()
    return {"ok": True, "case": get_case(case_id)}


def assign(case_id: str, assignee: str, actor: str = "operator") -> dict:
    init_db()
    assignee = (assignee or "").strip()
    con = _connect()
    row = con.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        con.close()
        return {"ok": False, "error": "case not found"}
    con.execute("UPDATE cases SET assignee=?, updated_at=? WHERE id=?", (assignee, _now(), case_id))
    _audit(con, case_id, actor, "assign", f"assignee={assignee}")
    con.commit()
    con.close()
    return {"ok": True, "case": get_case(case_id)}


def add_note(case_id: str, body: str, author: str = "operator") -> dict:
    init_db()
    body = (body or "").strip()
    if not body:
        return {"ok": False, "error": "note body required"}
    con = _connect()
    row = con.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        con.close()
        return {"ok": False, "error": "case not found"}
    con.execute(
        "INSERT INTO case_notes (case_id, author, body, created_at) VALUES (?,?,?,?)",
        (case_id, author or "operator", body[:4000], _now()),
    )
    con.execute("UPDATE cases SET updated_at=? WHERE id=?", (_now(), case_id))
    _audit(con, case_id, author or "operator", "note_add", f"len={len(body)}")
    con.commit()
    con.close()
    return {"ok": True, "case": get_case(case_id)}


def attach_alert(case_id: str, alert_ref: str, actor: str = "operator") -> dict:
    init_db()
    alert_ref = (alert_ref or "").strip()
    if not alert_ref:
        return {"ok": False, "error": "alert_ref required"}
    con = _connect()
    row = con.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        con.close()
        return {"ok": False, "error": "case not found"}
    con.execute(
        "INSERT OR IGNORE INTO case_alerts (case_id, alert_ref, attached_at) VALUES (?,?,?)",
        (case_id, alert_ref[:200], _now()),
    )
    con.execute("UPDATE cases SET updated_at=? WHERE id=?", (_now(), case_id))
    _audit(con, case_id, actor, "attach_alert", alert_ref[:200])
    con.commit()
    con.close()
    return {"ok": True, "case": get_case(case_id)}


def export_evidence(case_id: str, out_dir: Optional[Path] = None, actor: str = "operator") -> dict:
    """Build a signed-ish evidence pack (zip + sha256) for the case."""
    init_db()
    case = get_case(case_id)
    if not case:
        return {"ok": False, "error": "case not found"}

    base = Path(out_dir) if out_dir else (_home() / "data" / "evidence")
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pack_name = f"{case_id}_{stamp}"
    work = base / pack_name
    work.mkdir(parents=True, exist_ok=True)

    # Case JSON
    (work / "case.json").write_text(json.dumps(case, indent=2))

    # Attach recent alerts.log lines that match refs (best-effort)
    alerts_log = _home() / "data" / "alerts.log"
    matched = []
    if alerts_log.exists():
        refs = {a["ref"] for a in case.get("alert_refs") or []}
        for line in alerts_log.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            fp = str(rec.get("fp") or "")
            if fp in refs or (not refs and len(matched) < 20):
                matched.append(rec)
        (work / "alerts_matched.json").write_text(json.dumps(matched, indent=2))

    # Manifest + checksums
    manifest = {
        "case_id": case_id,
        "exported_at": _now(),
        "actor": actor,
        "files": [],
    }
    for f in sorted(work.iterdir()):
        if f.is_file():
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            manifest["files"].append({"name": f.name, "sha256": h, "bytes": f.stat().st_size})
    (work / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))

    zip_path = base / f"{pack_name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in work.iterdir():
            if f.is_file():
                zf.write(f, arcname=f"{pack_name}/{f.name}")

    sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    (base / f"{pack_name}.zip.sha256").write_text(f"{sha}  {zip_path.name}\n")

    # Cleanup work dir
    shutil.rmtree(work, ignore_errors=True)

    con = _connect()
    _audit(con, case_id, actor, "evidence_export", str(zip_path))
    con.execute("UPDATE cases SET updated_at=? WHERE id=?", (_now(), case_id))
    con.commit()
    con.close()

    return {
        "ok": True,
        "path": str(zip_path),
        "sha256": sha,
        "case_id": case_id,
        "files": manifest["files"],
    }


def create_from_normalized_alert(alert: dict, actor: str = "operator") -> dict:
    """Convenience: open a case from a NormalizedAlert-like dict."""
    title = alert.get("title") or "Imported alert"
    return create_case(
        title=title,
        severity=str(alert.get("severity") or "medium"),
        source=str(alert.get("source") or ""),
        source_event_id=str(alert.get("source_event_id") or alert.get("id") or ""),
        summary=str(alert.get("detail") or "")[:1000],
        actor=actor,
        alert_refs=[str(alert.get("id") or alert.get("source_event_id") or "")],
    )
