# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Opt-in canary SMB share (Linux Samba snippet + honey docs). Default OFF."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

HONEY = {
    "invoices.xlsx": "FAKE invoice ledger — canary\n",
    "passwords.txt": "admin:ChangeMe123 — canary do not use\n",
    "payroll.pdf": "%PDF-1.4 canary payroll placeholder\n",
    ".env": "AWS_SECRET_ACCESS_KEY=canary-not-real\nDB_PASSWORD=canary\n",
}


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def deploy_smb_canary(share_root: Optional[Path] = None) -> dict:
    root = share_root or (_home() / "data" / "smb_canary_share")
    root.mkdir(parents=True, exist_ok=True)
    tracker = []
    for name, content in HONEY.items():
        p = root / name
        p.write_text(content)
        try:
            os.chmod(p, 0o644)
        except Exception:
            pass
        tracker.append({"path": str(p), "name": name, "deployed": datetime.now().isoformat()})
    conf = f"""# SENTINEL canary share — append to smb.conf (requires samba)
# [sentinel-canary]
#    path = {root}
#    browseable = yes
#    read only = yes
#    guest ok = yes
#    comment = Shared Documents
"""
    conf_path = _home() / "data" / "smb_canary.conf.snippet"
    conf_path.write_text(conf)
    meta = {"share_root": str(root), "files": tracker, "snippet": str(conf_path)}
    (root / ".sentinel_canary_tracker.json").write_text(json.dumps(meta, indent=2))
    return {"ok": True, "share_root": str(root), "files": len(tracker), "samba_snippet": str(conf_path)}


def check_smb_canaries() -> list:
    """Return list of modified honey files (caller sends HIGH alerts)."""
    root = _home() / "data" / "smb_canary_share"
    tracker_path = root / ".sentinel_canary_tracker.json"
    if not tracker_path.exists():
        return []
    try:
        meta = json.loads(tracker_path.read_text())
    except Exception:
        return []
    hits = []
    for f in meta.get("files") or []:
        p = Path(f["path"])
        if not p.exists():
            hits.append({"path": str(p), "reason": "missing"})
            continue
        try:
            text = p.read_text(errors="ignore")
            expected = HONEY.get(f.get("name") or p.name, "")
            if expected and text != expected:
                hits.append({"path": str(p), "reason": "modified"})
        except Exception as e:
            hits.append({"path": str(p), "reason": str(e)})
    return hits
