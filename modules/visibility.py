# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Host + network visibility: devices, processes, FIM, persistence inventory.

Single entry point for "what is on this host / LAN right now" — used by
report, doctor-adjacent status, and continuous hunt enrichment.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


# ── Devices ──────────────────────────────────────────────────────────

def discover_arp() -> list[dict]:
    """Fast local-segment discovery via neighbor table (no nmap required)."""
    devices = []
    out = _run(["ip", "-4", "neigh", "show"]) or _run(["arp", "-an"])
    for line in out.splitlines():
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac_m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        if ip.endswith(".0") or ip.endswith(".255") or ip.startswith("127."):
            continue
        state = "unknown"
        for s in ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"):
            if s in line.upper():
                state = s.lower()
                break
        devices.append({
            "ip": ip,
            "mac": (mac_m.group(1).lower() if mac_m else "unknown"),
            "state": state,
            "source": "arp",
        })
    # de-dupe by IP
    by_ip = {d["ip"]: d for d in devices}
    return list(by_ip.values())


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def inventory_devices(
    send_alert: Optional[Callable] = None,
    logger=None,
) -> dict:
    """Merge ARP discovery with devices.json; flag new / returned / gone."""
    db_path = _data() / "devices.json"
    try:
        db = json.loads(db_path.read_text()) if db_path.exists() else {}
    except Exception:
        db = {}
    devices = dict(db.get("devices") or {})
    first_seen = dict(db.get("first_seen") or {})
    last_seen = dict(db.get("last_seen") or {})
    now = _now()

    found = discover_arp()
    # optional: device_radar known set
    try:
        from modules.device_radar import check as radar_check
        radar = radar_check()
    except Exception:
        radar = {"events": [], "devices": 0}

    new_list, seen_ips = [], set()
    for d in found:
        ip = d["ip"]
        seen_ips.add(ip)
        host = resolve_hostname(ip) or ip
        d["hostname"] = host
        if ip not in devices:
            entry = {
                **d,
                "hostname": host,
                "first_seen": now,
                "last_seen": now,
                "status": "new",
            }
            devices[ip] = entry
            first_seen[ip] = now
            last_seen[ip] = now
            new_list.append(entry)
            if send_alert:
                try:
                    send_alert("NEW_DEVICE", entry)
                except Exception:
                    pass
            if logger:
                logger.warning("NEW DEVICE %s (%s) mac=%s", host, ip, d.get("mac"))
        else:
            devices[ip]["last_seen"] = now
            devices[ip]["mac"] = d.get("mac") or devices[ip].get("mac")
            devices[ip]["state"] = d.get("state")
            if devices[ip].get("status") == "gone":
                devices[ip]["status"] = "returned"
                if send_alert:
                    try:
                        send_alert("DEVICE_RETURNED", devices[ip])
                    except Exception:
                        pass
            last_seen[ip] = now

    gone = []
    for ip, info in list(devices.items()):
        if ip not in seen_ips and info.get("source") == "arp":
            # only mark ARP-sourced as gone when missing from neigh
            if info.get("status") != "gone":
                info["status"] = "gone"
                gone.append(info)
                if send_alert:
                    try:
                        send_alert("DEVICE_GONE", {"ip": ip, "mac": info.get("mac")})
                    except Exception:
                        pass

    db = {
        "devices": devices,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_scans": int(db.get("total_scans") or 0) + 1,
        "last_inventory": now,
        "method": "arp+merge",
    }
    db_path.write_text(json.dumps(db, indent=2, default=str))
    snap = _data() / "visibility_devices.json"
    snap.write_text(json.dumps({"ts": now, "count": len(devices), "new": len(new_list), "gone": len(gone), "devices": devices}, indent=2, default=str))
    return {
        "ok": True,
        "count": len(devices),
        "live_arp": len(found),
        "new": new_list,
        "gone": gone,
        "radar_events": radar.get("events") or [],
        "path": str(db_path),
    }


# ── Processes ────────────────────────────────────────────────────────

def inventory_processes(top_n: int = 40) -> dict:
    """Snapshot of running processes with user, cpu, mem, exe."""
    out = _run(["ps", "auxww", "--no-headers"], timeout=12)
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
        cmd = parts[10]
        exe = cmd.split()[0] if cmd.split() else ""
        rows.append({
            "user": user,
            "pid": pid,
            "cpu": cpu,
            "mem": mem,
            "exe": exe,
            "command": cmd[:200],
        })
    # sort by CPU
    def _cpu(r):
        try:
            return float(r["cpu"])
        except Exception:
            return 0.0
    rows_sorted = sorted(rows, key=_cpu, reverse=True)
    by_user: dict[str, int] = {}
    for r in rows:
        by_user[r["user"]] = by_user.get(r["user"], 0) + 1
    snap = {
        "ts": _now(),
        "total": len(rows),
        "by_user": by_user,
        "top_cpu": rows_sorted[:top_n],
        "tmp_exec": [r for r in rows if r["exe"].startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))],
    }
    path = _data() / "visibility_processes.json"
    path.write_text(json.dumps(snap, indent=2, default=str))
    return {"ok": True, "total": len(rows), "by_user": by_user, "tmp_exec": len(snap["tmp_exec"]), "path": str(path), "top_cpu": snap["top_cpu"][:10]}


# ── Files / persistence ─────────────────────────────────────────────

def inventory_fim() -> dict:
    p = _data() / "integrity_baseline" / "integrity_baseline.json"
    if not p.exists():
        return {"ok": False, "baseline": False, "files": 0}
    try:
        data = json.loads(p.read_text())
        n = len(data) if isinstance(data, dict) else 0
        return {"ok": True, "baseline": True, "files": n, "path": str(p)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def inventory_persistence() -> dict:
    try:
        from modules.persistence_hunt import status, check
        st = status()
        ch = check() if st.get("baseline_exists") else {"count": 0, "events": []}
        return {
            "ok": True,
            "baseline_exists": st.get("baseline_exists"),
            "baseline_count": st.get("baseline_count"),
            "drift_events": ch.get("count", 0),
            "events": (ch.get("events") or [])[:10],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def inventory_suid() -> dict:
    try:
        from modules.fim_suid import status, check
        st = status()
        ch = check() if st.get("baseline_exists") else []
        return {
            "ok": True,
            "baseline_exists": st.get("baseline_exists"),
            "count": st.get("baseline_count"),
            "changes": len(ch) if isinstance(ch, list) else 0,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def full_inventory(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Complete visibility pass — devices + processes + FIM + persistence + SUID."""
    result = {
        "ok": True,
        "ts": _now(),
        "devices": inventory_devices(send_alert=send_alert, logger=logger),
        "processes": inventory_processes(),
        "fim": inventory_fim(),
        "persistence": inventory_persistence(),
        "suid": inventory_suid(),
    }
    path = _data() / "visibility_report.json"
    path.write_text(json.dumps(result, indent=2, default=str))
    result["report"] = str(path)
    return result


def print_inventory(result: dict) -> None:
    print()
    print("=" * 60)
    print("  SENTINEL VISIBILITY INVENTORY")
    print("=" * 60)
    d = result.get("devices") or {}
    print(f"  Devices:     {d.get('count', 0)} tracked · {d.get('live_arp', 0)} live ARP · "
          f"new={len(d.get('new') or [])} gone={len(d.get('gone') or [])}")
    for n in (d.get("new") or [])[:5]:
        print(f"    NEW  {n.get('ip')}  {n.get('mac')}  {n.get('hostname')}")
    p = result.get("processes") or {}
    print(f"  Processes:   {p.get('total', 0)} · tmp_exec={p.get('tmp_exec', 0)}")
    if p.get("by_user"):
        top_u = sorted(p["by_user"].items(), key=lambda x: -x[1])[:5]
        print(f"    by_user:   {', '.join(f'{u}={c}' for u, c in top_u)}")
    f = result.get("fim") or {}
    print(f"  FIM:         {'baseline ' + str(f.get('files')) + ' files' if f.get('baseline') else 'NO BASELINE'}")
    pr = result.get("persistence") or {}
    print(f"  Persistence: baseline={pr.get('baseline_count', '—')}  drift={pr.get('drift_events', 0)}")
    s = result.get("suid") or {}
    print(f"  SUID:        baseline={s.get('count', '—')}  changes={s.get('changes', 0)}")
    if result.get("report"):
        print(f"  Report:      {result['report']}")
    print("=" * 60)
    print()
