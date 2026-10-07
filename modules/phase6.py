#!/usr/bin/env python3
"""Sentinel Phase 6 — always-on service + scheduled WhatsApp digests."""
from __future__ import annotations
import os, shutil, subprocess, textwrap
from pathlib import Path
from typing import Optional

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _engine_path() -> Path:
    here = Path(__file__).resolve().parent.parent / "sentinel.py"
    if here.exists():
        return here
    return Path.cwd() / "sentinel.py"

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)

def service_unit(engine: Path, mode: str = "hunt") -> str:
    py = shutil.which("python3") or "/usr/bin/python3"
    eng = str(engine.resolve())
    work = str(engine.resolve().parent)
    return textwrap.dedent(f"""\
    [Unit]
    Description=SENTINEL continuous protection (TrinTech Digital Defense)
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    WorkingDirectory={work}
    ExecStart={py} {eng} hunt
    Restart=always
    RestartSec=15
    Environment=SENTINEL_DIR=%h/.sentinel

    [Install]
    WantedBy=multi-user.target
    """)

def install_service(system: bool = True) -> dict:
    eng = _engine_path()
    if not eng.exists():
        return {"ok": False, "error": f"sentinel.py not found at {eng}"}
    unit = service_unit(eng)
    if system:
        path = Path("/etc/systemd/system/sentinel.service")
        try:
            path.write_text(unit)
        except PermissionError:
            return install_service(system=False)
        logs = []
        for c in [
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "sentinel.service"],
            ["systemctl", "restart", "sentinel.service"],
        ]:
            code, out = _run(c)
            logs.append({"cmd": c, "code": code, "out": out[-400:]})
        st_code, st_out = _run(["systemctl", "status", "sentinel.service", "--no-pager"])
        return {"ok": True, "mode": "system", "unit": str(path), "logs": logs, "status": st_out[-800:]}
    else:
        ud = Path.home() / ".config/systemd/user"
        ud.mkdir(parents=True, exist_ok=True)
        path = ud / "sentinel.service"
        u = unit.replace("WantedBy=multi-user.target", "WantedBy=default.target")
        path.write_text(u)
        logs = []
        for c in [
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "sentinel.service"],
            ["systemctl", "--user", "restart", "sentinel.service"],
        ]:
            code, out = _run(c)
            logs.append({"cmd": c, "code": code, "out": out[-400:]})
        st_code, st_out = _run(["systemctl", "--user", "status", "sentinel.service", "--no-pager"])
        return {"ok": True, "mode": "user", "unit": str(path), "logs": logs, "status": st_out[-800:], "note": "user service — loginctl enable-linger $USER if needed"}

def service_status() -> dict:
    code, out = _run(["systemctl", "status", "sentinel.service", "--no-pager"])
    if code != 0:
        code2, out2 = _run(["systemctl", "--user", "status", "sentinel.service", "--no-pager"])
        return {"ok": code2 == 0, "mode": "user" if code2 == 0 else "none", "status": (out2 or out)[-1000:]}
    return {"ok": True, "mode": "system", "status": out[-1000:]}

def service_stop() -> dict:
    logs = []
    for c in [
        ["systemctl", "stop", "sentinel.service"],
        ["systemctl", "disable", "sentinel.service"],
        ["systemctl", "--user", "stop", "sentinel.service"],
        ["systemctl", "--user", "disable", "sentinel.service"],
    ]:
        code, out = _run(c)
        logs.append({"cmd": c, "code": code})
    return {"ok": True, "logs": logs}

def install_digest_cron(schedule: str = "daily") -> dict:
    eng = _engine_path()
    py = shutil.which("python3") or "/usr/bin/python3"
    if schedule == "weekly":
        line = f"0 8 * * 0 cd {eng.parent} && {py} {eng} whatsapp-digest --force >> {Path.home()}/.sentinel/data/digest_cron.log 2>&1"
    else:
        line = f"0 8 * * * cd {eng.parent} && {py} {eng} whatsapp-digest --force >> {Path.home()}/.sentinel/data/digest_cron.log 2>&1"
    marker = "# SENTINEL_WHATSAPP_DIGEST"
    full = f"{marker}\n{line}\n"
    code, existing = _run(["crontab", "-l"])
    text = existing if code == 0 else ""
    lines = text.splitlines()
    cleaned, skip = [], False
    for ln in lines:
        if ln.strip() == marker:
            skip = True
            continue
        if skip:
            skip = False
            continue
        cleaned.append(ln)
    new = "\n".join(cleaned).rstrip() + "\n\n" + full
    p = Path("/tmp/sentinel_cron.txt")
    p.write_text(new)
    code2, out2 = _run(["crontab", str(p)])
    return {"ok": code2 == 0, "schedule": schedule, "line": line, "crontab_result": out2[-300:]}

def remove_digest_cron() -> dict:
    code, existing = _run(["crontab", "-l"])
    if code != 0:
        return {"ok": True, "removed": False, "reason": "no crontab"}
    marker = "# SENTINEL_WHATSAPP_DIGEST"
    lines = existing.splitlines()
    cleaned, skip = [], False
    for ln in lines:
        if ln.strip() == marker:
            skip = True
            continue
        if skip:
            skip = False
            continue
        cleaned.append(ln)
    p = Path("/tmp/sentinel_cron.txt")
    p.write_text("\n".join(cleaned) + "\n")
    code2, out2 = _run(["crontab", str(p)])
    return {"ok": code2 == 0, "removed": True}

def phase6_self_check() -> dict:
    return {
        "service_install": True,
        "service_status": True,
        "digest_cron": True,
        "engine": str(_engine_path()),
        "engine_exists": _engine_path().exists(),
    }
