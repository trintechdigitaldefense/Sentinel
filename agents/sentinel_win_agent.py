"""
SENTINEL Windows Agent (feature 11) — pure stdlib + optional pywin32.

Capabilities:
  - FIM over user/system config-ish dirs
  - Process scan with reverse-shell heuristics
  - Heartbeat + event POST to central server

Install as service (admin):
  python sentinel_win_agent.py install
  python sentinel_win_agent.py start

Or run once:
  python sentinel_win_agent.py once --server https://central:8443 --key SECRET --client OFFICE1
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

RS_PATTERNS = [
    r"powershell.*-enc",
    r"powershell.*IEX",
    r"cmd\.exe.*/c.*powershell",
    r"nc\.exe",
    r"ncat",
    r"python.*-c.*socket",
]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def scan_processes() -> list:
    hits = []
    try:
        out = subprocess.check_output(["tasklist", "/FO", "CSV", "/V"], text=True, errors="ignore")
    except Exception:
        return hits
    for line in out.splitlines()[1:]:
        for pat in RS_PATTERNS:
            if re.search(pat, line, re.I):
                hits.append({"line": line[:200], "pattern": pat})
                break
    return hits


def fim_paths() -> list:
    home = Path.home()
    return [
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts",
    ]


def fim_snapshot() -> dict:
    snap = {}
    for p in fim_paths():
        try:
            if p.exists():
                if p.is_file():
                    h = hashlib.sha256(p.read_bytes()).hexdigest()
                    snap[str(p)] = h
                else:
                    snap[str(p)] = f"dir:{len(list(p.iterdir()))}"
        except Exception as e:
            snap[str(p)] = f"err:{e}"
    return snap


def post(server: str, key: str, path: str, body: dict) -> bool:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        server.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        return True
    except Exception as e:
        print("[!] post failed:", e)
        return False


def run_cycle(server: str, key: str, client_id: str) -> None:
    hits = scan_processes()
    for h in hits:
        post(server, key, "/v1/events", {
            "client_id": client_id,
            "severity": "CRITICAL",
            "title": "REVERSE_SHELL_HEURISTIC",
            "detail": h["line"],
            "ts": datetime.now().isoformat(),
        })
    post(server, key, "/v1/heartbeat", {
        "client_id": client_id,
        "ts": datetime.now().isoformat(),
        "fim": fim_snapshot(),
        "proc_hits": len(hits),
        "platform": "windows",
    })
    print(f"[+] cycle ok hits={len(hits)}")


def main():
    args = sys.argv[1:]
    server = _env("SENTINEL_SERVER")
    key = _env("SENTINEL_KEY")
    client = _env("SENTINEL_CLIENT", os.environ.get("COMPUTERNAME", "windows"))
    if "--server" in args:
        server = args[args.index("--server") + 1]
    if "--key" in args:
        key = args[args.index("--key") + 1]
    if "--client" in args:
        client = args[args.index("--client") + 1]
    if not args or args[0] == "once":
        if not server or not key:
            print("Usage: python sentinel_win_agent.py once --server URL --key KEY [--client ID]")
            sys.exit(1)
        run_cycle(server, key, client)
        return
    if args[0] == "loop":
        while True:
            run_cycle(server, key, client)
            time.sleep(300)
    if args[0] == "install":
        print("Install as Windows service with NSSM or pywin32 win32serviceutil in production.")
        print("For now: schtasks /Create /SC ONSTART /TN SentinelAgent /TR ...")
        return
    print("commands: once | loop | install")


if __name__ == "__main__":
    main()
