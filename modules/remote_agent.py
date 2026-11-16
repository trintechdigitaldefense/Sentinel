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
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import textwrap
from datetime import datetime
import ipaddress
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

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
        cfg = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            raise ValueError("configuration root must be a JSON object")
        return cfg
    except Exception as exc:
        raise RuntimeError(f"Sentinel config is unreadable; refusing to replace it: {exc}") from exc


def _save_cfg(cfg: dict) -> None:
    p = _home() / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".config.", suffix=".tmp", dir=str(p.parent))
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(cfg, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise



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
    return f"https://{ip}:{port}"


def bundles_dir() -> Path:
    d = _data() / "agent_bundles"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def agents_registry_path() -> Path:
    return _data() / "remote_agents.json"


def load_agents() -> dict:
    p = agents_registry_path()
    if not p.exists():
        return {"agents": {}}
    try:
        db = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(db, dict) or not isinstance(db.get("agents", {}), dict):
            raise ValueError("agent registry must contain an agents object")
        return db
    except Exception as exc:
        raise RuntimeError(f"remote agent registry is unreadable; refusing to reset it: {exc}") from exc


def save_agents(db: dict) -> None:
    p = agents_registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".remote_agents.", suffix=".tmp", dir=str(p.parent))
    tmp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(db, stream, indent=2, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def register_agent_checkin(payload: dict) -> dict:
    """Central-side: record agent heartbeat and update fleet canary status."""
    db = load_agents()
    host = payload.get("hostname") or payload.get("host") or "unknown"
    ip = payload.get("ip") or ""
    authenticated_agent_id = payload.get("agent_id")
    key = str(authenticated_agent_id or ip or host)
    entry = {
        "agent_id": authenticated_agent_id,
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
    url = (central_url or central_base_url()).rstrip("/")
    parsed_url = urlparse(url)
    if not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        raise ValueError("Central URL must have a hostname and must not contain credentials, query, or fragment")
    try:
        loopback = ipaddress.ip_address(parsed_url.hostname).is_loopback
    except ValueError:
        loopback = parsed_url.hostname.lower() == "localhost"
    if parsed_url.scheme != "https" and not (parsed_url.scheme == "http" and loopback):
        raise ValueError("Agent bundles require HTTPS for non-loopback central URLs")
    from modules.agent_keys import issue_key
    agent_id = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:80] or "agent"
    bootstrap_secret = secrets.token_urlsafe(32)
    issued = issue_key(agent_id, bootstrap_secret, bootstrap_secret, ttl_seconds=30 * 24 * 60 * 60)
    if not issued.get("ok"):
        raise RuntimeError("Could not issue per-agent credential")
    token = issued["api_key"]
    bdir = bundles_dir() / f"bundle_{agent_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
    bdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(bdir, 0o700)
    except OSError:
        pass
    token_path = bdir / "agent.key"
    token_path.write_text(token + "\n", encoding="utf-8")
    os.chmod(token_path, 0o600)

    # Include a configured private CA/certificate for strict TLS verification.
    central_cfg = _cfg()
    central_agent_cfg = central_cfg.get("agent") or {}
    configured_ca = central_agent_cfg.get("tls_ca") or central_agent_cfg.get("tls_cert")
    ca_path = None
    if configured_ca:
        source_ca = Path(str(configured_ca)).expanduser()
        if not source_ca.is_file():
            raise RuntimeError(f"Configured central CA/certificate does not exist: {source_ca}")
        ca_path = bdir / "central-ca.crt"
        shutil.copyfile(source_ca, ca_path)
        os.chmod(ca_path, 0o644)
    script = textwrap.dedent(f"""\
    #!/usr/bin/env bash
    # SENTINEL remote agent install - TrinTech Digital Defense
    # Authorized defensive use only. Run on the TARGET host.
    set -euo pipefail
    PYTHON_BIN="${{PYTHON:-python3}}"
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then echo "[!] Python executable not found: $PYTHON_BIN"; exit 1; fi
    PYTHON_BIN="$(command -v "$PYTHON_BIN")"
    CENTRAL_URL={shlex.quote(url)}
    SCRIPT_DIR="$(cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" && pwd)"
    TOKEN_FILE="${{SCRIPT_DIR}}/agent.key"
    CA_FILE="${{SCRIPT_DIR}}/central-ca.crt"
    SENTINEL_HOME="${{SENTINEL_DIR:-$HOME/.sentinel}}"
    if [[ ! -f "$TOKEN_FILE" ]]; then
      echo "[!] Missing agent.key sidecar; keep it beside install_agent.sh"
      exit 1
    fi
    SHARED_TOKEN="$(< "$TOKEN_FILE")"
    INSTALL_DIR="${{INSTALL_DIR:-$HOME/Sentinel}}"
    REPO_URL="${{REPO_URL:-https://github.com/trintechdigitaldefense/Sentinel.git}}"
    BRANCH="${{BRANCH:-main}}"

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
    "$PYTHON_BIN" setup.py

    mkdir -p "$SENTINEL_HOME"
    export SENTINEL_DIR="$SENTINEL_HOME"
    if [[ -f "$CA_FILE" ]]; then
      install -m 0644 "$CA_FILE" "$SENTINEL_HOME/central-ca.crt"
      export SENTINEL_TLS_CA="$SENTINEL_HOME/central-ca.crt"
    fi
    SENTINEL_AGENT_TOKEN="$SHARED_TOKEN" CENTRAL_URL="$CENTRAL_URL" SENTINEL_TLS_CA="${{SENTINEL_TLS_CA:-}}" "$PYTHON_BIN" - <<'PY'
import json, os
from pathlib import Path
p = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
cfg = {{}}
if p.exists():
    try:
        cfg = json.loads(p.read_text())
        if not isinstance(cfg, dict):
            raise ValueError("config root is not an object")
    except Exception as exc:
        raise SystemExit(f"Refusing to overwrite invalid config: {{exc}}")
cfg.setdefault("agent", {{}})
cfg["agent"]["shared_token"] = os.environ["SENTINEL_AGENT_TOKEN"]
cfg["agent"]["central_url"] = os.environ["CENTRAL_URL"]
cfg["agent"]["enabled"] = True
cfg["agent"]["role"] = "agent"
if os.environ.get("SENTINEL_TLS_CA"):
    cfg["agent"]["tls_ca"] = os.environ["SENTINEL_TLS_CA"]
tmp = p.with_suffix(".json.tmp")
tmp.write_text(json.dumps(cfg, indent=2))
os.chmod(tmp, 0o600)
os.replace(tmp, p)
os.chmod(p, 0o600)
print("[+] agent config written", p)
PY

    if [[ "${{SENTINEL_REMOVE_BUNDLE:-0}}" == "1" ]]; then
      rm -f "$TOKEN_FILE" "$CA_FILE"
    fi

    "$PYTHON_BIN" - <<'PY'
try:
    from modules.remote_agent import agent_plant_canaries
    print(agent_plant_canaries())
except Exception as e:
    print("[!] canary plant:", e)
    import subprocess, sys
    subprocess.call([sys.executable, "sentinel.py", "deception"])
PY

    echo "[*] Starting agent (reports to central every 60s)."

    # Prefer a systemd-managed service when the installer runs as root under systemd.
    # Containers, development and non-root installs retain foreground mode.
    if [[ "${{SENTINEL_FORCE_FOREGROUND:-0}}" != "1" \
          && "$(id -u)" -eq 0 \
          && -d /run/systemd/system \
          && command -v systemctl >/dev/null 2>&1 ]]; then
      RUN_USER="$(id -un)"
      RUN_HOME="$HOME"
      RUN_SENTINEL_DIR="$SENTINEL_HOME"
      UNIT_PATH="/etc/systemd/system/sentinel-agent.service"
      if [[ "$INSTALL_DIR" == *" "* || "$RUN_HOME" == *" "* || "$PYTHON_BIN" == *" "* ]]; then
        echo "[!] Spaces in install/home paths are unsupported for system service installation"
        exit 1
      fi
      cat > "$UNIT_PATH" <<EOF
    [Unit]
    Description=Sentinel remote security agent
    Wants=network-online.target
    After=network-online.target

    [Service]
    Type=simple
    User=$RUN_USER
    Environment=HOME=$RUN_HOME
    Environment=SENTINEL_DIR=$RUN_SENTINEL_DIR
    WorkingDirectory=$INSTALL_DIR
    ExecStart=$PYTHON_BIN $INSTALL_DIR/sentinel.py agent
    Restart=on-failure
    RestartSec=5
    TimeoutStopSec=30
    KillSignal=SIGTERM
    UMask=0077
    NoNewPrivileges=true
    PrivateTmp=true

    [Install]
    WantedBy=multi-user.target
    EOF
      chmod 0644 "$UNIT_PATH"
      systemctl daemon-reload
      systemctl enable sentinel-agent.service
      systemctl restart sentinel-agent.service 2>/dev/null || systemctl start sentinel-agent.service
      if ! systemctl is-active --quiet sentinel-agent.service; then
        systemctl --no-pager --full status sentinel-agent.service || true
        echo "[!] sentinel-agent.service failed to become active"
        exit 1
      fi
      echo "[+] sentinel-agent.service enabled and active"
      exit 0
    fi

    if [[ "${{SENTINEL_FORCE_FOREGROUND:-0}}" != "1" ]]; then
      echo "[=] systemd unavailable or installer is non-root; running agent in foreground"
    fi
    exec "$PYTHON_BIN" sentinel.py agent "$CENTRAL_URL"
    """)
    sh_path = bdir / "install_agent.sh"
    sh_path.write_text(script)
    try:
        os.chmod(sh_path, 0o700)
    except Exception as e:
        logging.getLogger('sentinel').debug('%s: %s', __name__, e)


    readme = textwrap.dedent(f"""\
    # Sentinel agent bundle - {label}

    Central: `{url}`
    Per-agent API key is stored in agent.key (0600); keep it beside the installer and treat both files as credentials.\n    The key expires after 30 days and must be reissued before expiry.

    ## Manual install on a remote Linux host
    1. Copy install_agent.sh and agent.key together to the host
    2. Keep agent.key in the same protected directory, then run bash install_agent.sh
    3. On a root-managed Linux host running systemd, the installer enables `sentinel-agent.service`; otherwise it runs the agent in the foreground

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
        "credential_file": str(token_path),
        "ca_file": str(ca_path) if ca_path else None,
        "credential_expires_in_seconds": 30 * 24 * 60 * 60,
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
    token_file = bundle["credential_file"]
    remote_dir = f"/tmp/sentinel_agent_bundle_{secrets.token_hex(6)}"
    remote_script = f"{remote_dir}/install_agent.sh"

    scp_cmd = ["scp", "-P", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    ssh_cmd = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity:
        scp_cmd.extend(["-i", identity])
        ssh_cmd.extend(["-i", identity])

    try:
        mkdir_cmd = ssh_cmd + [target, f"umask 077 && mkdir -m 700 -p {remote_dir}"]
        prepared = subprocess.run(mkdir_cmd, capture_output=True, text=True, timeout=30)
        if prepared.returncode != 0:
            return {"ok": False, "error": "could not prepare protected remote bundle directory", "stderr": (prepared.stderr or "")[:500], "bundle": bundle}
        transfer_files = [script, token_file]
        if bundle.get("ca_file"):
            transfer_files.append(bundle["ca_file"])
        scp_cmd.extend(transfer_files + [f"{target}:{remote_dir}/"])
        r1 = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if r1.returncode != 0:
            return {
                "ok": False,
                "error": "scp failed",
                "stderr": (r1.stderr or "")[:500],
                "hint": "Use an authorized key: ssh-copy-id user@host",
                "bundle": bundle,
            }
        remote = f"chmod 700 {remote_script} && chmod 600 {remote_dir}/agent.key && if [ -f {remote_dir}/central-ca.crt ]; then chmod 644 {remote_dir}/central-ca.crt; fi && (nohup bash -c 'SENTINEL_REMOVE_BUNDLE=1 bash {remote_script}; rc=$?; rm -rf {remote_dir}; exit $rc' >/tmp/sentinel-agent-install.log 2>&1 </dev/null & echo STARTED:$!)"
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
