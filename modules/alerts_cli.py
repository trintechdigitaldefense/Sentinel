# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Alert list / ack / suppress helpers (feature 6)."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _alerts_path() -> Path:
    return _home() / "data" / "alerts.log"


def _state_path() -> Path:
    return _home() / "data" / "alert_state.json"


def _load_state() -> dict:
    p = _state_path()
    if not p.exists():
        return {"acked": [], "suppressions": []}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"acked": [], "suppressions": []}


def _save_state(st: dict) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(st, indent=2))


def list_alerts(limit: int = 50, include_acked: bool = False) -> list:
    p = _alerts_path()
    if not p.exists():
        return []
    st = _load_state()
    acked = set(st.get("acked") or [])
    rows = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            rec = {"title": line, "severity": "INFO", "ts": ""}
        fp = rec.get("fp") or rec.get("ts") or ""
        if not include_acked and fp in acked:
            continue
        rows.append(rec)
    return rows[-limit:]


def ack_alert(fp_or_title: str) -> dict:
    st = _load_state()
    key = (fp_or_title or "").strip()
    if not key:
        return {"ok": False, "error": "empty id"}
    if key not in st["acked"]:
        st["acked"].append(key)
        _save_state(st)
    return {"ok": True, "acked": key, "total_acked": len(st["acked"])}


def add_suppression(detection_type: str, pattern: str, note: str = "") -> dict:
    st = _load_state()
    rule = {
        "id": f"sup-{int(datetime.now().timestamp())}",
        "detection_type": detection_type,
        "pattern": pattern,
        "note": note,
        "created": datetime.now().isoformat(),
    }
    st.setdefault("suppressions", []).append(rule)
    _save_state(st)
    return {"ok": True, **rule}


def is_suppressed(detection_type: str, text: str) -> bool:
    st = _load_state()
    for r in st.get("suppressions") or []:
        if r.get("detection_type") and r["detection_type"].upper() not in (detection_type or "").upper():
            if r["detection_type"] != "*":
                continue
        pat = r.get("pattern") or ""
        if pat and pat.lower() in (text or "").lower():
            return True
    return False
