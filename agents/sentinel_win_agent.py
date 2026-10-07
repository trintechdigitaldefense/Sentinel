# SENTINEL Windows Agent (limited) — TrinTech Digital Defense
# Requires: Python 3.10+ on Windows
# Usage: python sentinel_win_agent.py [--central http://CENTRAL:8790]

import json, os, socket, platform, argparse
from datetime import datetime
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

DATA = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
DATA.mkdir(parents=True, exist_ok=True)

def snapshot():
    procs = 0
    if HAS_PSUTIL:
        procs = len(list(psutil.process_iter()))
    else:
        try:
            import subprocess
            out = subprocess.check_output("tasklist", shell=True, text=True, errors="ignore")
            procs = max(0, len(out.splitlines()) - 3)
        except Exception:
            procs = -1
    return {
        "host": socket.gethostname(),
        "ip": None,
        "version": "2.6.0-win",
        "status": "ok",
        "os": "windows",
        "alerts_24h": 0,
        "scan_subnets": [],
        "heartbeat": {"ts": datetime.now().isoformat(), "procs": procs},
        "procs": procs,
        "platform": platform.platform(),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--central", default="")
    args = ap.parse_args()
    payload = snapshot()
    out = DATA / "win_agent_last.json"
    out.write_text(json.dumps(payload, indent=2))
    print("Wrote", out)
    if args.central:
        import urllib.request
        req = urllib.request.Request(
            args.central.rstrip("/") + "/api/report",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                print("Posted", resp.read().decode()[:200])
        except Exception as e:
            print("Post failed:", e)
    else:
        print(json.dumps(payload, indent=2))

if __name__ == "__main__":
    main()
