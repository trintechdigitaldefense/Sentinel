# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Remote Sentinel agent install + remote canary deployment.

Defensive multi-host expansion:
- Build install bundles (script + config token) for Linux hosts
- Optional SSH push when the operator provides user@host and key
- Agent-side canary plant on enroll/start
- Update fleet_devices.json when agents check in

Does not brute-force or exploit hosts — install requires authorized SSH
or manual run of the generated script on the target.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.remote_agent")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cfg() -> dict:
    p = _home() / "config.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_cfg(cfg: dict) -> None:
    p = _home() / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def ensure_agent_token() -> str:
    cfg = _cfg()
    agent = cfg.setdefault("agent", {})
    tok = agent.get("shared_token") or ""
    if not tok:
        tok = secrets.token_urlsafe(32)
        agent["shared_token"] = tok
        agent["enabled"] = True
        agent.setdefault("port", 8743)
        _save_cfg(cfg)
    return tok


def central_base_url() -> str:
    cfg = _cfg()
    agent = cfg.get("agent") or {}
    if agent.get("central_url"):
        return str(agent["central_url"]).rstrip("/")
    port = int(agent.get("port") or 8743)
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "127.0.0.1"
    return f"http://{ip}:{port}"


def bundles_dir() -> Path:
    d = _data() / "agent_bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def agents_registry_path() -> Path:
    return _data() / "remote_agents.json"


def load_agents() -> dict:
    p = agents_registry_path()
    if not p.exists():
        return {"agents": {}}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"agents": {}}


def save_agents(db: dict) -> None:
    agents_registry_path().write_text(json.dumps(db, indent=2, default=str))


def register_agent_checkin(payload: dict) -> dict:
    """Central-side: record agent heartbeat and update fleet canary status."""
    db = load_agents()
    host = payload.get("hostname") or payload.get("host") or "unknown"
    ip = payload.get("ip") or ""
    key = ip or host
    entry = {
        "hostname": host,
        "ip": ip,
        "last_seen": datetime.now().isoformat(),
        "canaries": payload.get("canaries") or {},
        "canary_count": len(payload.get("canaries") or {}),
        "processes_suspicious": len(payload.get("processes") or []),
        "raw_keys": list((payload.get("canaries") or {}).keys())[:20],
    }
    db.setdefault("agents", {})[key] = entry
    save_agents(db)

    try:
        from modules.network_fleet import load_devices, save_devices
        fleet = load_devices()
        devices = fleet.setdefault("devices", {})
        if ip and ip in devices:
            devices[ip]["canary"] = "planted-agent" if entry["canary_count"] else "agent-online"
            devices[ip]["protection"] = "agent"
            devices[ip]["agent_hostname"] = host
            devices[ip]["last_seen"] = entry["last_seen"]
            devices[ip]["status"] = devices[ip].get("status") or "approved"
        elif ip:
            devices[ip] = {
                "ip": ip,
                "mac": "",
                "source": "agent",
                "ports": [],
                "first_seen": entry["last_seen"],
                "last_seen": entry["last_seen"],
                "status": "agent",
                "canary": "planted-agent" if entry["canary_count"] else "agent-online",
                "protection": "agent",
                "agent_hostname": host,
            }
        fleet["count"] = len(devices)
        save_devices(fleet)
    except Exception:
        log.exception("fleet update from agent checkin")
    return {"ok": True, "key": key, "canary_count": entry["canary_count"]}


def build_install_bundle(
    central_url: Optional[str] = None,
    label: str = "default",
) -> dict:
    """Write install_agent.sh + README for manual or SSH install on a remote host."""
    token = ensure_agent_token()
    url = (central_url or central_base_url()).rstrip("/")
    bdir = bundles_dir() / f"bundle_{label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    bdir.mkdir(parents=True, exist_ok=True)

    script = textwrap.dedent(f"""\
    #!/usr/bin/env bash
    # SENTINEL remote agent install - TrinTech Digital Defense
    # Authorized defensive use only. Run on the TARGET host.
    set -euo pipefail
    CENTRAL_URL="{url}"
    SHARED_TOKEN="{token}"
    INSTALL_DIR="${{INSTALL_DIR:-$HOME/Sentinel}}"
    REPO_URL="${{REPO_URL:-https://github.com/trintechdigitaldefense/Sentinel.git}}"
    BRANCH="${{BRANCH:-hardening/production-readiness}}"

    echo "[*] Sentinel agent install -> $INSTALL_DIR"
    echo "[*] Central: $CENTRAL_URL"

    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
      if command -v git >/dev/null 2>&1; then
        git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || git clone "$REPO_URL" "$INSTALL_DIR"
      else
        echo "[!] git not found - copy the Sentinel tree to $INSTALL_DIR manually"
        exit 1
      fi
    else
      git -C "$INSTALL_DIR" fetch origin || true
      git -C "$INSTALL_DIR" checkout "$BRANCH" 2>/dev/null || true
      git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH" 2>/dev/null || true
    fi

    cd "$INSTALL_DIR"
    python3 setup.py || true

    mkdir -p "$HOME/.sentinel"
    python3 - <<PY
import json, os
from pathlib import Path
p = Path.home() / ".sentinel" / "config.json"
cfg = {{}}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
    except Exception:
        cfg = {{}}
cfg.setdefault("agent", {{}})
cfg["agent"]["shared_token"] = "{token}"
cfg["agent"]["central_url"] = "{url}"
cfg["agent"]["enabled"] = True
cfg["agent"]["role"] = "agent"
p.write_text(json.dumps(cfg, indent=2))
os.chmod(p, 0o600)
print("[+] agent config written", p)
PY

    python3 - <<'PY'
try:
    from modules.remote_agent import agent_plant_canaries
    print(agent_plant_canaries())
except Exception as e:
    print("[!] canary plant:", e)
    import subprocess, sys
    subprocess.call([sys.executable, "sentinel.py", "deception"])
PY

    echo "[*] Starting agent (reports to central every 60s)."
    echo "    Background: nohup python3 sentinel.py agent $CENTRAL_URL >/tmp/sentinel-agent.log 2>&1 &"
    exec python3 sentinel.py agent "$CENTRAL_URL"
    """)
    sh_path = bdir / "install_agent.sh"
    sh_path.write_text(script)
    try:
        os.chmod(sh_path, 0o755)
    except Exception:
        pass

    readme = textwrap.dedent(f"""\
    # Sentinel agent bundle - {label}

    Central: `{url}`
    Token is embedded in install_agent.sh (treat as secret).

    ## Manual install on a remote Linux host
    1. Copy install_agent.sh to the host
    2. bash install_agent.sh
    3. Leave agent running or use nohup

    ## SSH push from central (authorized key required)
    ```bash
    python3 sentinel.py agent-push user@HOST --identity ~/.ssh/id_ed25519
    ```

    Authorized defensive use only - TrinTech Digital Defense.
    """)
    (bdir / "README.md").write_text(readme)
    meta = {
        "ok": True,
        "bundle_dir": str(bdir),
        "install_script": str(sh_path),
        "central_url": url,
        "token_set": True,
        "label": label,
    }
    (bdir / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def agent_plant_canaries(logger: Any = None) -> dict:
    """On the agent host: deploy deception canaries and return summary."""
    try:
        eng = Path(__file__).resolve().parents[1] / "sentinel.py"
        r = subprocess.run(
            [os.environ.get("PYTHON", "python3"), str(eng), "deception"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        count = 0
        alt = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data" / "deception_artifacts" / "config.json"
        if alt.exists():
            try:
                count = len(json.loads(alt.read_text()))
            except Exception:
                count = 0
        out = {"ok": r.returncode == 0, "canary_files": count, "code": r.returncode}
        if logger:
            logger.info("agent canaries planted: %s", out)
        return out
    except Exception as e:
        log.exception("agent_plant_canaries")
        return {"ok": False, "error": str(e)}


def push_via_ssh(
    target: str,
    identity: Optional[str] = None,
    central_url: Optional[str] = None,
    port: int = 22,
    timeout: int = 120,
) -> dict:
    """Copy install script to user@host and start install under nohup."""
    if "@" not in target:
        return {"ok": False, "error": "target must be user@host"}
    if not shutil.which("ssh") or not shutil.which("scp"):
        return {"ok": False, "error": "ssh/scp not available on this machine"}

    label = target.replace("@", "_").replace(".", "_")[:40]
    bundle = build_install_bundle(central_url=central_url, label=label)
    script = bundle["install_script"]
    remote_script = f"/tmp/sentinel_install_agent_{secrets.token_hex(4)}.sh"

    scp_cmd = ["scp", "-P", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    ssh_cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity:
        scp_cmd.extend(["-i", identity])
        ssh_cmd.extend(["-i", identity])
    scp_cmd.extend([script, f"{target}:{remote_script}"])

    try:
        r1 = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if r1.returncode != 0:
            return {
                "ok": False,
                "error": "scp failed",
                "stderr": (r1.stderr or "")[:500],
                "hint": "Use an authorized key: ssh-copy-id user@host",
                "bundle": bundle,
            }
        remote = f"nohup bash {remote_script} >/tmp/sentinel-agent-install.log 2>&1 & echo STARTED:$!"
        r2 = subprocess.run(ssh_cmd + [target, remote], capture_output=True, text=True, timeout=timeout)
        return {
            "ok": r2.returncode == 0,
            "scp_code": r1.returncode,
            "ssh_code": r2.returncode,
            "stdout": (r2.stdout or "")[:400],
            "stderr": (r2.stderr or "")[:400],
            "bundle": bundle,
            "remote_log": "/tmp/sentinel-agent-install.log",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "bundle": bundle}
    except Exception as e:
        return {"ok": False, "error": str(e), "bundle": bundle}


def list_remote_agents() -> dict:
    db = load_agents()
    agents = db.get("agents") or {}
    return {"ok": True, "count": len(agents), "agents": agents}


def deploy_canaries_fleet_plan() -> dict:
    """Plan remote canaries and produce an install bundle for pending hosts."""
    try:
        from modules.network_fleet import plan_remote_canaries
    except Exception as e:
        return {"ok": False, "error": str(e)}
    plan = plan_remote_canaries()
    pending = plan.get("pending_agent_canaries") or []
    bundle = build_install_bundle(label="fleet")
    return {
        "ok": True,
        "pending_hosts": pending,
        "bundle": bundle,
        "instructions": (
            "For each pending host: python3 sentinel.py agent-push user@IP "
            "or copy install_agent.sh. When the agent checks in with canaries, "
            "fleet status becomes planted-agent."
        ),
    }
