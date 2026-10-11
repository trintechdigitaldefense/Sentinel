#!/usr/bin/env python3
"""
SENTINEL one-shot go — works WITH or WITHOUT systemd.
Clears integrity noise, deploys canaries, starts background hunt, prints dashboard URL.
"""
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOME = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
DATA = HOME / "data"
PIDFILE = DATA / "hunt.pid"
LOGFILE = DATA / "hunt_bg.log"


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=str(ROOT), **kw)


def step(msg):
    print(f"\n[*] {msg}")


def clear_integrity():
    step("Clear self-integrity false alarms")
    for p in (DATA / "self_integrity.json", HOME / "data" / "self_integrity.json"):
        if p.exists():
            p.unlink()
            print(f"    removed {p}")
    print("    ok")


def deploy_canaries():
    step("Deploy canaries / deception")
    r = run([sys.executable, "sentinel.py", "deception"], capture_output=True, text=True)
    lines = (r.stdout or r.stderr or "").strip().splitlines()
    for line in lines[-8:]:
        print("   ", line)
    if r.returncode != 0 and "deception" not in (r.stdout or ""):
        print("    (deception returned", r.returncode, "- continuing)")


def emit_heartbeat():
    step("Write heartbeat")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    code = (
        "from modules.phase5 import heartbeat_write; "
        "print(heartbeat_write({'source': 'go'}))"
    )
    r = run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    print("   ", (r.stdout or r.stderr or "").strip()[:200])


def stop_old_hunt():
    if PIDFILE.exists():
        try:
            pid = int(PIDFILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"    stopped old hunt pid={pid}")
            time.sleep(0.5)
        except Exception:
            pass
        try:
            PIDFILE.unlink()
        except Exception:
            pass


def start_bg_hunt():
    step("Start background hunt (no systemd needed)")
    stop_old_hunt()
    DATA.mkdir(parents=True, exist_ok=True)
    LOGFILE.write_text("")
    cmd = [sys.executable, str(ROOT / "sentinel.py"), "hunt"]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=open(LOGFILE, "a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    PIDFILE.write_text(str(proc.pid))
    print(f"    hunt pid={proc.pid}")
    print(f"    log → {LOGFILE}")
    time.sleep(2)
    try:
        os.kill(proc.pid, 0)
        print("    hunt is running")
    except OSError:
        print("    WARNING: hunt exited early — see log:")
        print(LOGFILE.read_text()[-500:])


def dashboard_url():
    step("Dashboard URL")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    code = (
        "from modules.dashboard import ensure_token; "
        "t,p,d=ensure_token(); "
        "print('URL=http://127.0.0.1:%d/?token=%s'%(p,t)); "
        "print('PORT',p); print('CONTROL', d.get('allow_control', True))"
    )
    r = run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    out = (r.stdout or r.stderr or "").strip()
    print("   ", out.replace("\n", "\n    "))
    return out


def try_systemd():
    step("systemd (optional)")
    r = run(["systemctl", "is-system-running"], capture_output=True, text=True)
    err = (r.stderr or "") + (r.stdout or "")
    if r.returncode != 0 or "offline" in err or "Host is down" in err or "not been booted" in err:
        print("    no systemd on this host — using background hunt instead")
        return False
    run([sys.executable, "sentinel.py", "service-install"])
    return True


def doctor():
    step("Doctor")
    run([sys.executable, "sentinel.py", "doctor"])


def main():
    print("=" * 56)
    print("  SENTINEL GO — one-shot activate")
    print("=" * 56)
    if not (ROOT / "sentinel.py").exists():
        print("[!] Run from the Sentinel repo directory")
        sys.exit(1)
    DATA.mkdir(parents=True, exist_ok=True)

    clear_integrity()
    deploy_canaries()
    emit_heartbeat()
    if not try_systemd():
        start_bg_hunt()
    else:
        time.sleep(1)
        emit_heartbeat()
    time.sleep(1)
    emit_heartbeat()
    dashboard_url()
    doctor()

    print()
    print("=" * 56)
    print("  READY")
    print("=" * 56)
    print()
    print("  Background hunt is running (or systemd if available).")
    print("  Start the dashboard UI:")
    print()
    print("      python3 sentinel.py dash")
    print()
    print("  Then open the URL it prints.")
    print()
    print("  Useful:")
    print("      tail -f ~/.sentinel/data/hunt_bg.log")
    print("      python3 sentinel.py doctor")
    print("      kill $(cat ~/.sentinel/data/hunt.pid)   # stop bg hunt")
    print()


if __name__ == "__main__":
    main()
