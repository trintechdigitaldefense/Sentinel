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
    st = service_status()
    # Enrich with heartbeat age
    try:
        from modules.dashboard_impl import collect_full
        d = collect_full()
        hb = d.get("heartbeat") or {}
        st["heartbeat"] = hb
        st["heartbeat_alive"] = bool(hb.get("alive"))
    except Exception as e:
        log.debug("heartbeat enrich: %s", e)
        st["heartbeat_alive"] = None
    st["summary"] = (
        f"{st.get('method')}:{st.get('status')}"
        + (f" pid={st['pid']}" if st.get("pid") else "")
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
