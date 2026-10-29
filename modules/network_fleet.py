# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Network-wide device discovery + fleet protection planning.

Discovers hosts on configured subnets (ARP first; rustscan/masscan/nmap
fallback). Tracks devices for the dashboard. Local canaries are planted on
this host; remote canaries require an enrolled agent (recorded as pending).

Supervised review: high-severity findings can be queued for operator
approval before they become client-visible critical flags.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("sentinel.network_fleet")


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
    except Exception as e:
        logging.getLogger('sentinel').debug('%s: %s', __name__, e)



def devices_path() -> Path:
    return _data() / "fleet_devices.json"


def review_path() -> Path:
    return _data() / "pending_review.json"


def load_devices() -> dict:
    p = devices_path()
    if not p.exists():
        return {"devices": {}, "updated": None, "scan_method": None}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"devices": {}, "updated": None, "scan_method": None}


def save_devices(db: dict) -> None:
    db["updated"] = datetime.now().isoformat()
    devices_path().write_text(json.dumps(db, indent=2, default=str))


def load_review() -> dict:
    p = review_path()
    if not p.exists():
        return {"pending": [], "approved": [], "rejected": []}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"pending": [], "approved": [], "rejected": []}


def save_review(db: dict) -> None:
    review_path().write_text(json.dumps(db, indent=2, default=str))


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def guess_subnets() -> list[str]:
    cfg = _cfg()
    nets = list((cfg.get("network") or {}).get("scan_subnets") or [])
    if nets:
        return nets
    # auto from local IPs
    code, out, _ = _run(["ip", "-4", "route", "show"], timeout=10)
    found = []
    for line in out.splitlines():
        m = re.search(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev", line)
        if m and not m.group(1).startswith("169.254"):
            found.append(m.group(1))
    if not found:
        found = ["192.168.1.0/24", "10.0.0.0/24"]
    return found


def discover_arp() -> list[dict]:
    devices = []
    code, out, _ = _run(["ip", "neigh", "show"], timeout=15)
    if code != 0 or not out.strip():
        code, out, _ = _run(["arp", "-an"], timeout=15)
    for line in out.splitlines():
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        if ip.endswith(".0") or ip.endswith(".255"):
            continue
        devices.append({
            "ip": ip,
            "mac": (mac_m.group(1).lower() if mac_m else ""),
            "source": "arp",
            "ports": [],
        })
    by_ip = {d["ip"]: d for d in devices}
    return list(by_ip.values())


def discover_fast_scan(subnets: list[str]) -> tuple[list[dict], str]:
    """Prefer rustscan → masscan → nmap -sn. Returns (devices, method)."""
    devices: dict[str, dict] = {}
    method = "none"

    rust = _which("rustscan")
    if rust and subnets:
        # rustscan -a range --ulimit 5000 -g  (greppable)
        for net in subnets[:3]:
            # expand poorly; pass CIDR if supported
            code, out, err = _run(
                [rust, "-a", net, "--ulimit", "5000", "-g", "--scripts", "None"],
                timeout=180,
            )
            if code == 0 or out.strip():
                method = "rustscan"
                for line in out.splitlines():
                    # Open 192.168.1.5:22
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
                    if not m:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if m:
                            ip = m.group(1)
                            devices.setdefault(ip, {"ip": ip, "mac": "", "source": "rustscan", "ports": []})
                        continue
                    ip, port = m.group(1), int(m.group(2))
                    ent = devices.setdefault(ip, {"ip": ip, "mac": "", "source": "rustscan", "ports": []})
                    if port not in ent["ports"]:
                        ent["ports"].append(port)
        if devices:
            return list(devices.values()), method

    mass = _which("masscan")
    if mass and subnets:
        method = "masscan"
        for net in subnets[:3]:
            # common ports only — defensive discovery
            code, out, err = _run(
                [mass, net, "-p22,80,443,445,3389,8080,8443", "--rate", "500", "-oL", "-"],
                timeout=180,
            )
            for line in out.splitlines():
                # open tcp 22 192.168.1.5
                m = re.search(r"open\s+tcp\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line, re.I)
                if not m:
                    continue
                port, ip = int(m.group(1)), m.group(2)
                ent = devices.setdefault(ip, {"ip": ip, "mac": "", "source": "masscan", "ports": []})
                if port not in ent["ports"]:
                    ent["ports"].append(port)
        if devices:
            return list(devices.values()), method

    nmap = _which("nmap")
    if nmap and subnets:
        method = "nmap"
        for net in subnets[:3]:
            code, out, err = _run([nmap, "-sn", "-T4", net, "-oG", "-"], timeout=180)
            for line in out.splitlines():
                if "Up" not in line and "Status: Up" not in line:
                    continue
                m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip = m.group(1)
                    devices.setdefault(ip, {"ip": ip, "mac": "", "source": "nmap", "ports": []})
        if devices:
            return list(devices.values()), method

    return [], method


def merge_discovery(logger: Any = None) -> dict:
    """ARP + optional fast scanners → fleet_devices.json."""
    subnets = guess_subnets()
    arp = discover_arp()
    scanned, method = discover_fast_scan(subnets)
    by_ip: dict[str, dict] = {}
    now = datetime.now().isoformat()

    for d in arp + scanned:
        ip = d["ip"]
        if ip not in by_ip:
            by_ip[ip] = {
                "ip": ip,
                "mac": d.get("mac") or "",
                "source": d.get("source"),
                "ports": list(d.get("ports") or []),
                "first_seen": now,
                "last_seen": now,
                "status": "discovered",
                "canary": "none",
                "protection": "network-visible",
            }
        else:
            by_ip[ip]["last_seen"] = now
            if d.get("mac"):
                by_ip[ip]["mac"] = d["mac"]
            for p in d.get("ports") or []:
                if p not in by_ip[ip]["ports"]:
                    by_ip[ip]["ports"].append(p)
            # prefer richer source label
            if d.get("source") in ("rustscan", "masscan", "nmap"):
                by_ip[ip]["source"] = d["source"]

    # localhost
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "127.0.0.1"
    by_ip.setdefault(local_ip, {
        "ip": local_ip,
        "mac": "",
        "source": "local",
        "ports": [],
        "first_seen": now,
        "last_seen": now,
        "status": "local",
        "canary": "none",
        "protection": "full-local",
    })
    by_ip[local_ip]["status"] = "local"
    by_ip[local_ip]["protection"] = "full-local"

    prev = load_devices()
    prev_map = dict(prev.get("devices") or {})
    new_ips = []
    for ip, ent in by_ip.items():
        if ip in prev_map:
            old = prev_map[ip]
            ent["first_seen"] = old.get("first_seen") or ent["first_seen"]
            ent["canary"] = old.get("canary") or ent["canary"]
            if old.get("status") == "approved":
                ent["status"] = "approved"
        else:
            if ent.get("status") != "local":
                new_ips.append(ip)
                ent["status"] = "new"

    db = {
        "devices": by_ip,
        "scan_method": method if method != "none" else ("arp" if arp else "none"),
        "subnets": subnets,
        "new_ips": new_ips,
        "count": len(by_ip),
        "tools": {
            "rustscan": bool(_which("rustscan")),
            "masscan": bool(_which("masscan")),
            "nmap": bool(_which("nmap")),
        },
    }
    save_devices(db)
    # Supervised: new devices wait for operator before client-critical noise
    if supervised_enabled() and new_ips:
        for ip in new_ips[:20]:
            try:
                queue_for_review(
                    "NEW_DEVICE",
                    {"ip": ip, "device": by_ip.get(ip)},
                    severity="MEDIUM",
                )
            except Exception:
                log.exception("queue new device")
    if logger:
        try:
            logger.info("Fleet discovery: %s hosts via %s (new=%s)", len(by_ip), db["scan_method"], len(new_ips))
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)

    return db


def plant_local_canaries(logger: Any = None) -> dict:
    """Deploy deception canaries on THIS host only."""
    try:
        # Prefer existing deception deploy path in engine
        from pathlib import Path as P
        import sys
        eng = P(__file__).resolve().parents[1] / "sentinel.py"
        # Call deploy via subprocess to avoid circular imports
        code, out, err = _run([sys.executable, str(eng), "deception"], timeout=120)
        result = {"ok": code == 0, "code": code, "note": "local canaries via deception"}
        # Mark local devices
        db = load_devices()
        for ip, ent in (db.get("devices") or {}).items():
            if ent.get("status") == "local" or ent.get("protection") == "full-local":
                ent["canary"] = "planted-local"
        save_devices(db)
        if logger:
            logger.info("Local canaries: ok=%s", result["ok"])
        return result
    except Exception as e:
        log.exception("plant_local_canaries")
        return {"ok": False, "error": str(e)}


def plan_remote_canaries() -> dict:
    """Record remote devices needing agent-based canary deploy (no remote write without agent)."""
    db = load_devices()
    pending = []
    for ip, ent in (db.get("devices") or {}).items():
        if ent.get("status") == "local" or ent.get("protection") == "full-local":
            continue
        if ent.get("canary") in ("planted-local", "planted-agent"):
            continue
        ent["canary"] = "pending-agent"
        ent["protection"] = "network-visible+agent-required"
        pending.append(ip)
    save_devices(db)
    return {
        "ok": True,
        "pending_agent_canaries": pending,
        "message": "Remote canary files require a Sentinel agent on each host. "
                   "Network-visible devices are tracked; install agents to plant canaries remotely.",
    }


def queue_for_review(event_type: str, payload: dict, severity: str = "HIGH") -> dict:
    """Hold a finding for operator oversight before client-critical flagging."""
    db = load_review()
    item = {
        "id": f"rv-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(db.get('pending') or [])}",
        "ts": datetime.now().isoformat(),
        "type": event_type,
        "severity": severity,
        "payload": payload,
        "status": "pending",
    }
    db.setdefault("pending", []).append(item)
    # cap
    db["pending"] = db["pending"][-200:]
    save_review(db)
    return {"ok": True, "id": item["id"], "queued": True}


def list_pending_review() -> list:
    return list(load_review().get("pending") or [])


def resolve_review(item_id: str, decision: str = "approve") -> dict:
    db = load_review()
    pending = db.get("pending") or []
    found = None
    rest = []
    for it in pending:
        if it.get("id") == item_id:
            found = it
        else:
            rest.append(it)
    if not found:
        return {"ok": False, "error": "not found"}
    found["status"] = decision
    found["resolved_ts"] = datetime.now().isoformat()
    db["pending"] = rest
    key = "approved" if decision == "approve" else "rejected"
    db.setdefault(key, []).append(found)
    db[key] = db[key][-100:]
    save_review(db)
    return {"ok": True, "id": item_id, "decision": decision, "item": found}


def supervised_enabled() -> bool:
    cfg = _cfg()
    return bool((cfg.get("alerting") or {}).get("supervised_review", True))


def set_supervised(enabled: bool) -> dict:
    cfg = _cfg()
    cfg.setdefault("alerting", {})["supervised_review"] = bool(enabled)
    _save_cfg(cfg)
    return {"ok": True, "supervised_review": bool(enabled)}


def fleet_status() -> dict:
    db = load_devices()
    rev = load_review()
    devices = db.get("devices") or {}
    return {
        "ok": True,
        "count": len(devices),
        "scan_method": db.get("scan_method"),
        "subnets": db.get("subnets") or [],
        "tools": db.get("tools") or {},
        "new_ips": db.get("new_ips") or [],
        "canary_planted": sum(1 for d in devices.values() if str(d.get("canary", "")).startswith("planted")),
        "canary_pending_agent": sum(1 for d in devices.values() if d.get("canary") == "pending-agent"),
        "pending_review": len(rev.get("pending") or []),
        "devices": devices,
        "updated": db.get("updated"),
    }


def continuous_protect_bootstrap(logger: Any = None) -> dict:
    """One-shot bootstrap before long-running hunt: discover, local canaries, plan remote."""
    steps = {}
    try:
        steps["discovery"] = merge_discovery(logger=logger)
    except Exception as e:
        log.exception("discovery")
        steps["discovery"] = {"ok": False, "error": str(e)}
    try:
        steps["local_canaries"] = plant_local_canaries(logger=logger)
    except Exception as e:
        steps["local_canaries"] = {"ok": False, "error": str(e)}
    try:
        steps["remote_plan"] = plan_remote_canaries()
    except Exception as e:
        steps["remote_plan"] = {"ok": False, "error": str(e)}
    steps["supervised_review"] = supervised_enabled()
    steps["fleet"] = fleet_status()
    return {"ok": True, "steps": steps}
