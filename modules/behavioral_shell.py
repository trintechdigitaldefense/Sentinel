#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Behavioral reverse-shell heuristics beyond cmdline pattern matching.

Signals:
  1. /proc/<pid>/exe points to a deleted binary (classic post-exec wipe)
  2. Process has an interactive TTY AND at least one established TCP socket
  3. Parent-child anomaly: web server / php-fpm / nginx spawning a shell
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Optional

WEB_PARENTS = re.compile(
    r"(nginx|apache2?|httpd|php-fpm|caddy|lighttpd|tomcat|node|uwsgi|gunicorn)",
    re.I,
)
SHELL_NAMES = re.compile(r"(^|/)(ba)?sh$|(^|/)dash$|(^|/)zsh$|(^|/)ash$|(^|/)csh$|(^|/)python[23]?$|(^|/)perl$|(^|/)nc$|(^|/)ncat$|(^|/)socat$")


def _read(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return default


def _exe_deleted(pid: str) -> bool:
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        return "deleted" in target
    except Exception:
        return False


def _has_tty(pid: str) -> bool:
    """True if fd 0 links to a pts/tty device."""
    try:
        t = os.readlink(f"/proc/{pid}/fd/0")
        return "pts" in t or "tty" in t
    except Exception:
        return False


def _has_tcp(pid: str) -> bool:
    """True if process has an established TCP socket (inode match in /proc/net/tcp)."""
    try:
        inodes = set()
        fd_dir = Path(f"/proc/{pid}/fd")
        for fd in fd_dir.iterdir():
            try:
                link = os.readlink(fd)
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
            except Exception:
                continue
        if not inodes:
            return False
        for netf in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                lines = Path(netf).read_text().splitlines()[1:]
            except Exception:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                # state 01 = ESTABLISHED
                if parts[3] != "01":
                    continue
                inode = parts[9]
                if inode in inodes:
                    return True
    except Exception:
        pass
    return False


def _cmdline(pid: str) -> str:
    raw = _read(f"/proc/{pid}/cmdline")
    return raw.replace("\x00", " ").strip()


def _comm(pid: str) -> str:
    return _read(f"/proc/{pid}/comm").strip()


def _ppid_and_parent_comm(pid: str) -> tuple[str, str]:
    try:
        # /proc/pid/stat: pid (comm) state ppid ...
        st = _read(f"/proc/{pid}/stat")
        # comm can contain spaces in parentheses
        rparen = st.rfind(")")
        after = st[rparen + 2 :].split()
        ppid = after[1] if len(after) > 1 else "0"
        return ppid, _comm(ppid)
    except Exception:
        return "0", ""


def scan(send_alert: Optional[Callable] = None, logger=None) -> list:
    """Scan /proc for behavioral reverse-shell indicators."""
    hits = []
    try:
        pids = [p.name for p in Path("/proc").iterdir() if p.name.isdigit()]
    except Exception:
        return hits

    for pid in pids:
        try:
            # Skip kernel threads (no cmdline)
            cmd = _cmdline(pid)
            if not cmd and not _comm(pid):
                continue
            # Skip ourselves
            if "sentinel" in cmd.lower():
                continue

            reasons = []

            if _exe_deleted(pid):
                reasons.append("deleted_exe")

            tty = _has_tty(pid)
            tcp = _has_tcp(pid)
            if tty and tcp:
                reasons.append("tty_and_tcp")

            ppid, pcomm = _ppid_and_parent_comm(pid)
            child = _comm(pid)
            if WEB_PARENTS.search(pcomm or "") and SHELL_NAMES.search(child or cmd.split()[0] if cmd else ""):
                reasons.append(f"web_parent_shell:{pcomm}->{child}")

            if not reasons:
                continue

            rec = {
                "pid": pid,
                "ppid": ppid,
                "user": _read(f"/proc/{pid}/status").split("Uid:")[1].split()[0] if "Uid:" in _read(f"/proc/{pid}/status") else "?",
                "command": (cmd or child)[:200],
                "reasons": reasons,
                "parent": pcomm,
            }
            hits.append(rec)
            if logger:
                logger.warning(
                    "BEHAVIORAL SHELL pid=%s reasons=%s cmd=%s",
                    pid, ",".join(reasons), rec["command"][:80],
                )
            if send_alert:
                try:
                    send_alert("BEHAVIORAL_REVERSE_SHELL", rec)
                except Exception:
                    pass
        except Exception:
            continue

    return hits
