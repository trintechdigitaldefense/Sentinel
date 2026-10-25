# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SUID/SGID inventory + privilege-escalation drift detection.

Baselines the set of setuid/setgid binaries and alerts on:
  - NEW SUID/SGID binary (highest signal)
  - REMOVED expected SUID binary
  - mode/owner change on known SUID paths
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

SEARCH_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _baseline_path() -> Path:
    p = _home() / "data" / "suid_baseline.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan() -> dict:
    """Return {path: {mode, uid, gid, size, suid, sgid}} for setuid/setgid files."""
    out: dict = {}
    cmd = ["find"] + SEARCH_PATHS + ["-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "2>/dev/null"]
    # Use shell-free find
    try:
        r = subprocess.run(
            ["find"] + SEARCH_PATHS + ["-xdev", "-type", "f", "-perm", "/6000"],
            capture_output=True, text=True, timeout=30,
        )
        paths = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    except Exception:
        paths = []

    for fpath in paths:
        try:
            st = os.lstat(fpath)
            mode = st.st_mode
            out[fpath] = {
                "mode": oct(stat.S_IMODE(mode)),
                "mode_int": stat.S_IMODE(mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "size": st.st_size,
                "suid": bool(mode & stat.S_ISUID),
                "sgid": bool(mode & stat.S_ISGID),
                "mtime": int(st.st_mtime),
            }
        except Exception:
            continue
    return out


def build_baseline() -> dict:
    inv = _scan()
    data = {"updated": _now(), "count": len(inv), "binaries": inv}
    _baseline_path().write_text(json.dumps(data, indent=2))
    return {"ok": True, "count": len(inv), "path": str(_baseline_path())}


def check(send_alert: Optional[Callable] = None, logger=None) -> list:
    """Compare live SUID/SGID set to baseline. Returns list of change dicts."""
    path = _baseline_path()
    if not path.exists():
        # First run — build silently
        build_baseline()
        if logger:
            logger.info("SUID baseline created (%s binaries)" % len(_scan()))
        return []

    try:
        base = json.loads(path.read_text())
        old = base.get("binaries") or {}
    except Exception:
        build_baseline()
        return []

    live = _scan()
    changes = []

    # New SUID/SGID
    for fpath, meta in live.items():
        if fpath not in old:
            rec = {"type": "NEW_SUID", "file": fpath, **meta}
            changes.append(rec)
            if logger:
                logger.warning("NEW SUID/SGID binary: %s mode=%s uid=%s", fpath, meta.get("mode"), meta.get("uid"))
            if send_alert:
                try:
                    send_alert("NEW_SUID", {"file": fpath, "mode": meta.get("mode"), "uid": meta.get("uid"), "gid": meta.get("gid")})
                except Exception:
                    pass
        else:
            prev = old[fpath]
            if prev.get("mode_int") != meta.get("mode_int") or prev.get("uid") != meta.get("uid") or prev.get("gid") != meta.get("gid"):
                rec = {"type": "SUID_META_CHANGE", "file": fpath, "old": prev, "new": meta}
                changes.append(rec)
                if logger:
                    logger.warning("SUID metadata change: %s", fpath)
                if send_alert:
                    try:
                        send_alert("SUID_META_CHANGE", {"file": fpath, "old": prev, "new": meta})
                    except Exception:
                        pass

    # Removed expected SUID (may be legitimate package update — still signal)
    for fpath in old:
        if fpath not in live:
            rec = {"type": "REMOVED_SUID", "file": fpath, "old": old[fpath]}
            changes.append(rec)
            if logger:
                logger.warning("Expected SUID binary missing: %s", fpath)
            if send_alert:
                try:
                    send_alert("REMOVED_SUID", {"file": fpath})
                except Exception:
                    pass

    return changes


def status() -> dict:
    p = _baseline_path()
    live = _scan()
    base_count = 0
    if p.exists():
        try:
            base_count = int((json.loads(p.read_text()) or {}).get("count") or 0)
        except Exception:
            pass
    return {
        "ok": True,
        "baseline_exists": p.exists(),
        "baseline_count": base_count,
        "live_count": len(live),
        "path": str(p),
    }
