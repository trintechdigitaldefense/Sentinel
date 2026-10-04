#!/usr/bin/env python3
"""
Sentinel Phase 1 modules — TrinTech Digital Defense
Import and wire from sentinel.py main / send_alert / agent paths.

Features:
  - Quiet mode + severity filtering
  - Auto-quarantine playbook
  - Canary beacon helpers
  - Client onboard helper
  - TLS-ready agent report headers
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

QUARANTINE_DIR_NAME = "quarantine"
CRITICAL_ALERTS = {
    "REVERSE_SHELL",
    "CANARY_TRIGGERED",
    "CANARY_BEACON",
    "AGENT_REVERSE_SHELL",
    "SELF_INTEGRITY_VIOLATION",
}


def quiet_should_emit(config: dict, alert_type: str, details: Any = None) -> bool:
    """Return False if quiet mode says suppress this alert."""
    q = config.get("quiet", {})
    if not q.get("enabled", False):
        return True

    suppress = set(q.get("suppress_types", []) or [])
    if alert_type in suppress:
        return False

    min_sev = (q.get("min_severity") or "low").lower()
    high_types = CRITICAL_ALERTS
    if min_sev in ("high", "critical") and alert_type not in high_types:
        if min_sev == "high" and alert_type not in high_types:
            return False

    cmd = ""
    if isinstance(details, dict):
        cmd = str(details.get("command") or details.get("cmd") or "")
    for frag in q.get("whitelist_processes", []) or []:
        if frag and frag.lower() in cmd.lower():
            return False

    try:
        rate = int(q.get("rate_limit_minutes", 0) or 0)
    except Exception:
        rate = 0
    if rate > 0:
        stamp_file = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data" / "quiet_rate.json"
        now = datetime.now()
        state = {}
        if stamp_file.exists():
            try:
                state = json.loads(stamp_file.read_text())
            except Exception:
                state = {}
        last = state.get(alert_type)
        if last:
            try:
                if now - datetime.fromisoformat(last) < timedelta(minutes=rate):
                    return False
            except Exception:
                pass
        state[alert_type] = now.isoformat()
        try:
            stamp_file.parent.mkdir(parents=True, exist_ok=True)
            stamp_file.write_text(json.dumps(state, indent=2))
        except Exception:
            pass

    return True


def quarantine_dir(data_dir: Path) -> Path:
    d = data_dir / QUARANTINE_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def auto_quarantine(config: dict, alert_type: str, details: dict, logger=None, run_cmd=None, send_alert=None):
    """Execute quarantine playbook on high-severity alerts."""
    qc = config.get("quarantine", {})
    if not qc.get("enabled", True):
        return {"actions": []}

    on_alerts = set(qc.get("on_alerts") or list(CRITICAL_ALERTS))
    if alert_type not in on_alerts:
        return {"actions": []}

    actions = []
    data_dir = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    qdir = quarantine_dir(data_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        evidence = qdir / f"{alert_type}_{ts}.json"
        evidence.write_text(json.dumps({"alert": alert_type, "details": details, "time": datetime.now().isoformat()}, indent=2))
        actions.append(f"evidence:{evidence}")
    except Exception:
        pass

    pid = details.get("pid") if isinstance(details, dict) else None
    if qc.get("kill_process", True) and pid:
        try:
            if run_cmd:
                run_cmd(["kill", "-9", str(pid)], timeout=5)
            else:
                subprocess.run(["kill", "-9", str(pid)], capture_output=True, timeout=5)
            actions.append(f"killed_pid:{pid}")
            if logger:
                logger.warning(f"QUARANTINE: killed PID {pid}")
        except Exception as e:
            actions.append(f"kill_failed:{e}")

    ip = None
    if isinstance(details, dict):
        ip = details.get("ip") or details.get("source_ip")
    if qc.get("block_ip", True) and ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(ip)):
        try:
            cmd = f"iptables -I INPUT -s {ip} -j DROP"
            if run_cmd:
                run_cmd(cmd, timeout=5)
            else:
                subprocess.run(cmd.split(), capture_output=True, timeout=5)
            actions.append(f"blocked_ip:{ip}")
            if logger:
                logger.warning(f"QUARANTINE: blocked IP {ip}")
        except Exception as e:
            actions.append(f"block_failed:{e}")

    user = details.get("user") if isinstance(details, dict) else None
    if qc.get("lock_user", False) and user and user not in ("root", "nobody"):
        try:
            subprocess.run(["usermod", "-L", str(user)], capture_output=True, timeout=5)
            actions.append(f"locked_user:{user}")
        except Exception as e:
            actions.append(f"lock_failed:{e}")

    if actions and send_alert:
        try:
            send_alert("QUARANTINE_ACTION", {"parent_alert": alert_type, "actions": actions, "details": details}, logger)
        except Exception:
            pass

    return {"actions": actions}


def embed_canary_beacon(content: str, canary_id: str, central_url: str = "") -> str:
    """Append beacon marker / URL into decoy content."""
    marker = f"\n# SENTINEL-CANARY-ID: {canary_id}\n"
    if central_url:
        beacon = central_url.rstrip("/") + f"/canary/beacon?id={canary_id}"
        marker += f"# SENTINEL-BEACON: {beacon}\n"
    return content + marker


def handle_canary_beacon(canary_id: str, request_meta: dict, config: dict, logger=None, send_alert=None, auto_quarantine_fn=None):
    """Called when GET /canary/beacon?id=... hits central."""
    details = {"canary_id": canary_id, "meta": request_meta}
    if send_alert:
        send_alert("CANARY_BEACON", details, logger)
    if auto_quarantine_fn:
        auto_quarantine_fn(config, "CANARY_BEACON", details, logger=logger)
    if logger:
        logger.warning(f"CANARY BEACON HIT: {canary_id}")
    return {"status": "recorded", "canary_id": canary_id}


def client_onboard(config: dict, client_name: str, subnets=None, logger=None,
                   deploy_deception=None, fim_build_baseline=None, config_file=None):
    """One-command client onboarding."""
    client_name = (client_name or "client").strip()
    config.setdefault("client", {})["name"] = client_name
    agent = config.setdefault("agent", {})
    if not agent.get("shared_token"):
        agent["shared_token"] = secrets.token_urlsafe(32)
    agent["enabled"] = True
    agent.setdefault("port", 8743)

    if subnets:
        config.setdefault("network", {})["scan_subnets"] = list(subnets)

    config.setdefault("quiet", {
        "enabled": False,
        "min_severity": "medium",
        "suppress_types": [],
        "rate_limit_minutes": 10,
        "whitelist_processes": ["sentinel", "systemd", "sshd"],
        "whitelist_ips": [],
    })
    config.setdefault("quarantine", {
        "enabled": True,
        "on_alerts": list(CRITICAL_ALERTS),
        "block_ip": True,
        "kill_process": True,
        "lock_user": False,
    })

    if config_file:
        Path(config_file).write_text(json.dumps(config, indent=2))

    if deploy_deception:
        deploy_deception(config, logger)
    if fim_build_baseline:
        fim_build_baseline(config, logger)

    token = agent.get("shared_token", "")
    port = agent.get("port", 8743)
    summary = {
        "client": client_name,
        "shared_token": token,
        "agent_install": f"python3 sentinel.py agent http://CENTRAL_IP:{port}",
        "note": "Copy shared_token into every agent config.json under agent.shared_token",
    }
    if logger:
        logger.info(f"Onboarded client: {client_name}")
        logger.info(f"Token: {token}")
        logger.info(f"Agent: {summary['agent_install']}")
    return summary


def phase1_self_check(config: dict) -> dict:
    agent = config.get("agent", {})
    return {
        "token_set": bool(agent.get("shared_token")),
        "quarantine_enabled": config.get("quarantine", {}).get("enabled", False),
        "quiet_enabled": config.get("quiet", {}).get("enabled", False),
        "client_name": config.get("client", {}).get("name", ""),
        "agent_port": agent.get("port", 8743),
        "use_tls": agent.get("use_tls", False),
    }


def tls_agent_headers(token: str, extra=None) -> dict:
    h = {
        "Content-Type": "application/json",
        "X-Sentinel-Token": token or "",
        "X-Sentinel-Phase": "1",
    }
    if extra:
        h.update(extra)
    return h
