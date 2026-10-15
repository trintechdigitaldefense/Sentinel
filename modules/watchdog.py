"""Health watchdog + heartbeat (feature 14)."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.watchdog")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def host_stats() -> dict:
    disk = shutil.disk_usage(str(Path.home()))
    mem = {}
    try:
        txt = Path("/proc/meminfo").read_text()
        for line in txt.splitlines():
            if line.startswith("MemTotal:") or line.startswith("MemAvailable:"):
                k, v, *_ = line.split()
                mem[k[:-1]] = int(v)
    except Exception:
        pass
    return {
        "disk_total": disk.total,
        "disk_free": disk.free,
        "disk_used_pct": round(100 * (disk.used / disk.total), 1) if disk.total else 0,
        "mem": mem,
        "ts": datetime.now().isoformat(),
    }


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def ensure_hunt(repo: Path) -> dict:
    pidfile = _home() / "data" / "hunt.pid"
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text().strip())
            if pid_alive(pid):
                return {"ok": True, "running": True, "pid": pid}
        except Exception:
            pass
    # restart
    logf = open(_home() / "data" / "hunt_bg.log", "a")
    proc = subprocess.Popen(
        [os.environ.get("PYTHON", "python3"), str(repo / "sentinel.py"), "hunt"],
        cwd=str(repo),
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text(str(proc.pid))
    log.warning("watchdog restarted hunt pid=%s", proc.pid)
    return {"ok": True, "restarted": True, "pid": proc.pid}


def send_central_heartbeat(central_cfg: dict, client_id: str = "local") -> dict:
    if not (central_cfg or {}).get("enabled"):
        return {"ok": False, "skipped": True}
    url = (central_cfg.get("server_url") or "").rstrip("/") + "/v1/heartbeat"
    key = central_cfg.get("api_key") or ""
    import urllib.request

    body = json.dumps({"client_id": client_id, "stats": host_stats()}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json", "X-API-Key": key}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def run_watchdog(repo: Path, central_cfg: Optional[dict] = None, interval: int = 60) -> None:
    log.info("watchdog started interval=%ss", interval)
    while True:
        try:
            ensure_hunt(repo)
            send_central_heartbeat(central_cfg or {}, client_id=os.uname().nodename if hasattr(os, "uname") else "host")
        except Exception as e:
            log.error("watchdog loop: %s", e)
        time.sleep(interval)
