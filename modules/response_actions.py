# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Opt-in containment actions (feature 7). Default ALL OFF."""
from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.response")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _audit_path() -> Path:
    return _home() / "data" / "response_audit.jsonl"


def _record(action: str, target: str, ok: bool, detail: str = "") -> dict:
    rec = {
        "ts": datetime.now().isoformat(),
        "action": action,
        "target": target,
        "ok": ok,
        "detail": detail,
        "reversible_hint": _hint(action, target),
    }
    p = _audit_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
    log.warning("response action %s target=%s ok=%s %s", action, target, ok, detail)
    return rec


def _hint(action: str, target: str) -> str:
    if action == "kill_process":
        return "Process already terminated; restart service manually if legitimate"
    if action == "block_ip":
        return f"sudo iptables -D INPUT -s {target} -j DROP  # or nft delete"
    if action == "disable_user":
        return f"sudo usermod -U {target}  # re-enable"
    return ""


def kill_process(pid: int, cfg: dict) -> dict:
    if not (cfg or {}).get("enabled") or not (cfg or {}).get("kill_process"):
        return {"ok": False, "error": "kill_process disabled in config.response"}
    try:
        os.kill(int(pid), 15)
        return _record("kill_process", str(pid), True, "SIGTERM")
    except Exception as e:
        return _record("kill_process", str(pid), False, str(e))


def block_ip(ip: str, cfg: dict) -> dict:
    if not (cfg or {}).get("enabled") or not (cfg or {}).get("block_ip"):
        return {"ok": False, "error": "block_ip disabled in config.response"}
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "empty ip"}
    # prefer iptables, fall back to nft
    try:
        r = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10,
        )
        ok = r.returncode == 0
        return _record("block_ip", ip, ok, r.stderr or r.stdout or "")
    except FileNotFoundError:
        try:
            r = subprocess.run(
                ["nft", "insert", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                capture_output=True, text=True, timeout=10,
            )
            return _record("block_ip", ip, r.returncode == 0, r.stderr or "")
        except Exception as e:
            return _record("block_ip", ip, False, str(e))
    except Exception as e:
        return _record("block_ip", ip, False, str(e))


def disable_user(username: str, cfg: dict) -> dict:
    if not (cfg or {}).get("enabled") or not (cfg or {}).get("disable_user"):
        return {"ok": False, "error": "disable_user disabled in config.response"}
    username = (username or "").strip()
    if not username or username in ("root",):
        return {"ok": False, "error": "refusing empty or root"}
    try:
        r = subprocess.run(["usermod", "-L", username], capture_output=True, text=True, timeout=10)
        return _record("disable_user", username, r.returncode == 0, r.stderr or "")
    except Exception as e:
        return _record("disable_user", username, False, str(e))
