#!/usr/bin/env python3
"""FEATURE 11 — Heartbeat dead-man's switch (sensor offline detection)."""
from __future__ import annotations
import json
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_INTERVAL = 300
DEFAULT_TIMEOUT = 600

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def deadman_config() -> dict:
    c = _cfg()
    dm = c.get("deadman") or {}
    return {
        "enabled": dm.get("enabled", True),
        "interval_sec": int(dm.get("interval_sec") or DEFAULT_INTERVAL),
        "timeout_sec": int(dm.get("timeout_sec") or DEFAULT_TIMEOUT),
    }

def emit_heartbeat(source: str = "hunt", extra: Optional[dict] = None) -> dict:
    payload = {
        "ts": datetime.now().isoformat(),
        "source": source,
        "host": socket.gethostname(),
        "alive": True,
    }
    if extra:
        payload.update(extra)
    path = _data() / "heartbeat.json"
    path.write_text(json.dumps(payload, indent=2))
    try:
        agents = _data() / "agents"
        agents.mkdir(parents=True, exist_ok=True)
        host = payload["host"].replace("/", "_")[:80]
        ap = agents / f"{host}.json"
        row = {}
        if ap.exists():
            try:
                row = json.loads(ap.read_text())
            except Exception:
                row = {}
        row.update({
            "host": payload["host"],
            "received_at": payload["ts"],
            "heartbeat": payload,
            "status": "ok",
            "os": row.get("os", "linux"),
        })
        ap.write_text(json.dumps(row, indent=2))
    except Exception:
        pass
    return payload

def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", ""))
    except Exception:
        return None

def check_local() -> dict:
    cfg = deadman_config()
    path = _data() / "heartbeat.json"
    if not path.exists():
        return {
            "ok": False,
            "alive": False,
            "status": "MISSING",
            "detail": "no heartbeat.json — start hunt or service-install",
            "timeout_sec": cfg["timeout_sec"],
        }
    try:
        d = json.loads(path.read_text())
    except Exception as e:
        return {"ok": False, "alive": False, "status": "ERROR", "detail": str(e)}
    ts = _parse_ts(d.get("ts") or d.get("timestamp") or "")
    if not ts:
        return {"ok": False, "alive": False, "status": "BAD_TS", "detail": d}
    age = int((datetime.now() - ts).total_seconds())
    alive = age <= cfg["timeout_sec"]
    return {
        "ok": alive,
        "alive": alive,
        "status": "ALIVE" if alive else "STALE",
        "age_sec": age,
        "timeout_sec": cfg["timeout_sec"],
        "source": d.get("source"),
        "host": d.get("host"),
        "ts": d.get("ts"),
        "detail": f"last heartbeat {age}s ago (timeout {cfg['timeout_sec']}s)",
    }

def check_fleet() -> dict:
    cfg = deadman_config()
    if not cfg["enabled"]:
        return {"ok": True, "enabled": False, "offline": [], "alive": [], "detail": "deadman disabled"}
    agents_dir = _data() / "agents"
    offline = []
    alive = []
    if not agents_dir.exists():
        local = check_local()
        if not local.get("alive"):
            offline.append({"host": local.get("host") or "local", **local})
        else:
            alive.append(local)
        return {
            "ok": len(offline) == 0,
            "enabled": True,
            "offline": offline,
            "alive": alive,
            "timeout_sec": cfg["timeout_sec"],
        }
    now = datetime.now()
    for p in sorted(agents_dir.glob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        host = d.get("host") or p.stem
        ts = _parse_ts(d.get("received_at") or (d.get("heartbeat") or {}).get("ts") or "")
        if not ts:
            offline.append({"host": host, "status": "NO_TS", "detail": "no received_at"})
            continue
        age = int((now - ts).total_seconds())
        row = {"host": host, "age_sec": age, "ts": ts.isoformat(), "status": "ALIVE" if age <= cfg["timeout_sec"] else "OFFLINE"}
        if age > cfg["timeout_sec"]:
            row["detail"] = f"no heartbeat for {age}s (limit {cfg['timeout_sec']}s)"
            offline.append(row)
        else:
            alive.append(row)
    return {
        "ok": len(offline) == 0,
        "enabled": True,
        "offline": offline,
        "alive": alive,
        "timeout_sec": cfg["timeout_sec"],
        "alert": (
            f"DEADMAN: {len(offline)} monitoring host(s) offline: "
            + ", ".join(o["host"] for o in offline)
            if offline else None
        ),
    }

def print_status() -> dict:
    local = check_local()
    fleet = check_fleet()
    print()
    print("=" * 56)
    print("  SENTINEL DEAD-MAN SWITCH")
    print("=" * 56)
    print(f"  Local:  {local.get('status')} — {local.get('detail')}")
    print(f"  Fleet:  {len(fleet.get('alive') or [])} alive · {len(fleet.get('offline') or [])} offline")
    if fleet.get("alert"):
        print(f"  ALERT:  {fleet['alert']}")
    for o in fleet.get("offline") or []:
        print(f"    ! {o.get('host')}: {o.get('detail') or o.get('status')}")
    print("=" * 56)
    print()
    return {"local": local, "fleet": fleet}

def ensure_defaults() -> None:
    p = _home() / "config.json"
    c = {}
    if p.exists():
        try:
            c = json.loads(p.read_text())
        except Exception:
            c = {}
    dm = c.setdefault("deadman", {})
    dm.setdefault("enabled", True)
    dm.setdefault("interval_sec", DEFAULT_INTERVAL)
    dm.setdefault("timeout_sec", DEFAULT_TIMEOUT)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(c, indent=2))
