# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Real-time FIM via inotifywait (or polling fallback).

Watches critical directories for create/modify/delete/attrib and raises
FIM_REALTIME / FIM_ATTRIB alerts. Designed to run as `sentinel watch`
or alongside the hunt loop for short bursts.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

DEFAULT_DIRS = [
    "/etc",
    "/etc/ssh",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def watch_dirs(config: dict | None = None) -> list[str]:
    fim = (config or {}).get("fim") or {}
    dirs = list(fim.get("watch_dirs") or DEFAULT_DIRS)
    extra = fim.get("extra_watch_dirs") or []
    for d in extra:
        if d not in dirs:
            dirs.append(d)
    # Only existing dirs
    return [d for d in dirs if os.path.isdir(d)]


def has_inotifywait() -> bool:
    return shutil.which("inotifywait") is not None


def visibility_status() -> dict:
    """Report whether realtime FIM can observe events fully."""
    ok = has_inotifywait()
    return {
        "ok": True,
        "inotifywait": ok,
        "mode": "inotify" if ok else "poll_or_unavailable",
        "incomplete": not ok,
        "detail": None if ok else "inotifywait not installed — realtime FIM coverage reduced",
    }


def run_watch(
    config: dict,
    send_alert: Optional[Callable] = None,
    logger=None,
    duration: int = 0,
) -> dict:
    """Block and watch. duration=0 means until Ctrl+C; else seconds.

    Uses a single inotifywait process with multiple paths (efficient).
    """
    dirs = watch_dirs(config)
    if not dirs:
        if logger:
            logger.warning("No watchable directories")
        return {"ok": False, "error": "no dirs"}

    if not has_inotifywait():
        if logger:
            logger.warning("inotifywait not installed — install inotify-tools for real-time FIM")
            logger.info("Falling back to 30s polling of critical files")
        return _poll_fallback(config, send_alert, logger, duration or 120)

    if logger:
        logger.info("Real-time FIM watching %d dirs via inotifywait", len(dirs))

    cmd = [
        "inotifywait", "-q", "-m", "-r",
        "--format", "%e|%w%f",
        "-e", "modify,create,delete,attrib,moved_to,moved_from",
    ] + dirs

    events = 0
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        start = time.time()
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line or "|" not in line:
                continue
            event, filepath = line.split("|", 1)
            # Noise filters
            low = filepath.lower()
            if any(x in low for x in ("/sentinel", ".sentinel/", "__pycache__", ".pyc", "swp", ".tmp")):
                continue
            events += 1
            is_attrib = "ATTRIB" in event.upper()
            is_delete = "DELETE" in event.upper()
            is_create = "CREATE" in event.upper() or "MOVED_TO" in event.upper()

            if logger:
                logger.warning("FIM realtime %s: %s", event, filepath)

            if send_alert:
                kind = "FIM_ATTRIB" if is_attrib else (
                    "LOG_TAMPERING" if is_delete and "/var/log" in filepath else "FIM_REALTIME"
                )
                try:
                    send_alert(kind, {"event": event, "file": filepath, "create": is_create, "delete": is_delete})
                except Exception:
                    pass

            if duration and (time.time() - start) >= duration:
                proc.terminate()
                break
    except KeyboardInterrupt:
        if logger:
            logger.info("Realtime FIM stopped by user")
    except Exception as e:
        if logger:
            logger.warning("Realtime FIM error: %s", e)
        return {"ok": False, "error": str(e), "events": events}

    return {"ok": True, "events": events, "dirs": dirs, "backend": "inotifywait"}


def _poll_fallback(config, send_alert, logger, duration: int) -> dict:
    """Hash a small critical set every few seconds when inotify is unavailable."""
    files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
        "/etc/crontab", "/root/.ssh/authorized_keys",
    ]
    import hashlib
    def h(p):
        try:
            return hashlib.sha256(Path(p).read_bytes()).hexdigest()
        except Exception:
            return None
    snap = {f: h(f) for f in files if os.path.exists(f)}
    end = time.time() + duration
    events = 0
    while time.time() < end:
        time.sleep(5)
        for f in list(snap.keys()):
            nh = h(f)
            if nh and snap[f] and nh != snap[f]:
                events += 1
                if logger:
                    logger.warning("FIM poll change: %s", f)
                if send_alert:
                    try:
                        send_alert("FIM_REALTIME", {"event": "MODIFY", "file": f, "backend": "poll"})
                    except Exception:
                        pass
                snap[f] = nh
    return {"ok": True, "events": events, "backend": "poll"}
