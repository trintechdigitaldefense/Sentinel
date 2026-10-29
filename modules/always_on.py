# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Always-on hunt service helpers (systemd or background)."""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("sentinel.always_on")


def install() -> dict[str, Any]:
    from modules.phase5 import service_install
    return service_install()


def status() -> dict[str, Any]:
    from modules.phase5 import service_status
    st = dict(service_status() or {})
    hb = {}
    try:
        from modules.phase5 import heartbeat_status
        hs = heartbeat_status()
        if isinstance(hs, dict):
            hb = {**(hs.get("data") or {}), **{k: hs.get(k) for k in ("alive", "age_seconds", "ok")}}
            st["heartbeat"] = hb
            st["heartbeat_alive"] = bool(hs.get("alive"))
    except Exception as e:
        log.debug("heartbeat enrich: %s", e)
        st["heartbeat_alive"] = None

    # If service not installed but heartbeat is fresh, monitoring is still active
    method = st.get("method") or "none"
    status = str(st.get("status") or "")
    alive = bool(st.get("heartbeat_alive"))
    if (not st.get("ok") or method == "none" or "not installed" in status.lower() or status.lower() == "not running"):
        if alive:
            st["ok"] = True
            st["method"] = st.get("method") if st.get("method") not in (None, "none") else "heartbeat"
            st["status"] = "monitoring (heartbeat alive — install service for restart-on-boot)"
            st["note"] = "run: python3 sentinel.py service-install for true always-on"
    st["summary"] = (
        f"{st.get('method')}:{st.get('status')}"
        + (f" pid={st['pid']}" if st.get("pid") else "")
        + (f" hb={st.get('heartbeat_age_seconds') or hb.get('age_seconds')}s" if alive else "")
    )
    return st


def stop() -> dict[str, Any]:
    """Stop systemd unit or background hunt pid."""
    import os
    import shutil
    import subprocess
    from pathlib import Path

    out: dict[str, Any] = {"ok": False}
    if shutil.which("systemctl") and Path("/run/systemd/system").exists():
        subprocess.run(["systemctl", "stop", "sentinel-hunt"], capture_output=True)
        subprocess.run(["systemctl", "disable", "sentinel-hunt"], capture_output=True)
        out.update({"ok": True, "method": "systemd", "status": "stopped"})
        return out
    try:
        from modules.phase5 import _data
        data = _data()
    except Exception:
        data = Path.home() / ".sentinel" / "data"
    pidfile = Path(data) / "hunt.pid"
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 15)
            pidfile.unlink(missing_ok=True)
            out.update({"ok": True, "method": "background", "status": "stopped", "pid": pid})
            return out
        except Exception as e:
            out["error"] = str(e)
            return out
    out.update({"ok": True, "method": "none", "status": "not running"})
    return out
