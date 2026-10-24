# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Install / run scheduled open-cases digests (Phase 10)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _repo_guess() -> Path:
    here = Path(__file__).resolve()
    if (here.parents[1] / "sentinel.py").exists():
        return here.parents[1]
    cwd = Path.cwd()
    if (cwd / "sentinel.py").exists():
        return cwd
    return cwd


def run_digest_job(via: str = "auto") -> dict:
    from modules.msp_digest import send_digest, format_digest

    result = send_digest(via=via)
    out = _home() / "data" / "last_digest.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    text = result.get("text") or format_digest()
    out.write_text(text)
    result["saved"] = str(out)
    return result


def crontab_line(hour: int = 8, minute: int = 0, repo: Optional[Path] = None) -> str:
    repo = repo or _repo_guess()
    py = shutil.which("python3") or "python3"
    log = _home() / "logs" / "digest-cron.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    return (
        f"{minute} {hour} * * * cd {repo} && "
        f'{py} -c "from modules.digest_cron import run_digest_job; run_digest_job()" '
        f">> {log} 2>&1"
    )


def install_crontab(hour: int = 8, minute: int = 0) -> dict:
    line = crontab_line(hour=hour, minute=minute)
    marker = "modules.digest_cron"
    try:
        current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = current.stdout if current.returncode == 0 else ""
    except FileNotFoundError:
        return {"ok": False, "error": "crontab not available on this host", "line": line}
    lines = [ln for ln in existing.splitlines() if marker not in ln]
    lines.append(line)
    new = "\n".join(lines).rstrip() + "\n"
    p = subprocess.run(["crontab", "-"], input=new, text=True, capture_output=True)
    if p.returncode != 0:
        return {"ok": False, "error": p.stderr or "crontab install failed", "line": line}
    return {"ok": True, "line": line, "method": "crontab"}


def install_systemd_user(hour: int = 8, minute: int = 0) -> dict:
    if not shutil.which("systemctl"):
        return {"ok": False, "error": "systemctl not found"}
    repo = _repo_guess()
    py = shutil.which("python3") or "python3"
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    service = unit_dir / "sentinel-digest.service"
    timer = unit_dir / "sentinel-digest.timer"
    service.write_text(
        f"[Unit]\nDescription=SENTINEL open-cases digest\n\n"
        f"[Service]\nType=oneshot\nWorkingDirectory={repo}\n"
        f'ExecStart={py} -c "from modules.digest_cron import run_digest_job; run_digest_job()"\n'
    )
    timer.write_text(
        f"[Unit]\nDescription=Daily SENTINEL cases digest\n\n"
        f"[Timer]\nOnCalendar=*-*-* {hour:02d}:{minute:02d}:00\nPersistent=true\n\n"
        f"[Install]\nWantedBy=timers.target\n"
    )
    for c in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", "sentinel-digest.timer"],
    ):
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0:
            return {
                "ok": False,
                "error": (r.stderr or r.stdout or "systemctl failed").strip(),
                "service": str(service),
                "timer": str(timer),
            }
    return {"ok": True, "method": "systemd-user", "service": str(service), "timer": str(timer)}


def install(hour: int = 8, minute: int = 0, prefer: str = "auto") -> dict:
    prefer = (prefer or "auto").lower()
    if prefer in ("systemd", "auto"):
        r = install_systemd_user(hour=hour, minute=minute)
        if r.get("ok") or prefer == "systemd":
            return r
    return install_crontab(hour=hour, minute=minute)
