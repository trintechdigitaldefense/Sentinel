# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Ops snapshot: hunt health, alerts rate, service, offline queue, blocks."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    return _home() / "data"


def collect() -> dict:
    out: dict[str, Any] = {"ok": True, "ts": datetime.now(timezone.utc).isoformat()}

    # Hunt metrics
    mp = _data() / "hunt_metrics.json"
    if mp.exists():
        try:
            out["hunt"] = json.loads(mp.read_text())
        except Exception as e:
            out["hunt"] = {"error": str(e)}
    else:
        out["hunt"] = {"cycles": 0, "note": "no cycles yet — start hunt or service"}

    # Heartbeat
    hb = _data() / "heartbeat.json"
    if hb.exists():
        try:
            out["heartbeat"] = json.loads(hb.read_text())
        except Exception:
            out["heartbeat"] = {"present": True}
    else:
        out["heartbeat"] = {"present": False}

    # Alerts tail
    alerts = _data() / "alerts.log"
    recent = []
    count = 0
    if alerts.exists():
        try:
            lines = alerts.read_text(errors="ignore").splitlines()
            count = len(lines)
            for ln in lines[-15:]:
                try:
                    recent.append(json.loads(ln))
                except Exception:
                    recent.append({"raw": ln[:120]})
        except Exception:
            pass
    out["alerts"] = {"total": count, "recent": recent}

    # Offline queue
    oq = _data() / "offline_queue.jsonl"
    oqn = 0
    if oq.exists():
        oqn = sum(1 for ln in oq.read_text().splitlines() if ln.strip())
    out["offline_queue"] = oqn

    # SSH blocks
    try:
        from modules.brute_force import status as bf_status
        out["ssh_blocks"] = bf_status()
    except Exception as e:
        out["ssh_blocks"] = {"error": str(e)}

    # Service
    try:
        from modules.phase5 import service_status
        out["service"] = service_status()
    except Exception as e:
        out["service"] = {"error": str(e)}

    # Visibility snapshot summary
    vr = _data() / "visibility_report.json"
    if vr.exists():
        try:
            v = json.loads(vr.read_text())
            out["visibility"] = {
                "devices": (v.get("devices") or {}).get("count"),
                "processes": (v.get("processes") or {}).get("total"),
                "fim": (v.get("fim") or {}).get("files"),
            }
        except Exception:
            out["visibility"] = {}

    return out


def print_ops(data: dict) -> None:
    print()
    print("=" * 60)
    print("  SENTINEL OPS STATUS")
    print("=" * 60)
    h = data.get("hunt") or {}
    print(f"  Hunt cycles:     {h.get('cycles', 0)}")
    print(f"  Last cycle:      {h.get('last_cycle_sec')}s  ok={h.get('last_ok')}")
    print(f"  Last ts:         {h.get('last_ts', '—')}")
    print(f"  Session alerts:  {h.get('alerts_this_session', 0)}")
    if h.get("last_errors"):
        print(f"  Last errors:     {h['last_errors'][:3]}")
    hb = data.get("heartbeat") or {}
    print(f"  Heartbeat:       {hb.get('present', hb.get('ts', False))}")
    a = data.get("alerts") or {}
    print(f"  Alerts total:    {a.get('total', 0)}")
    print(f"  Offline queue:   {data.get('offline_queue', 0)}")
    sb = data.get("ssh_blocks") or {}
    print(f"  SSH blocks:      {sb.get('active_blocks', '—')}")
    svc = data.get("service") or {}
    print(f"  Service:         {svc.get('status') or svc}")
    vis = data.get("visibility") or {}
    if vis:
        print(f"  Visibility:      devices={vis.get('devices')} procs={vis.get('processes')} fim={vis.get('files')}")
    recent = (a.get("recent") or [])[-5:]
    if recent:
        print("  Recent alerts:")
        for r in recent:
            t = r.get("type") or r.get("title") or r.get("raw") or "?"
            print(f"    · {t}")
    print("=" * 60)
    print()
