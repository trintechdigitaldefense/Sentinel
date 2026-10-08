#!/usr/bin/env python3
"""
SENTINEL single install path — TrinTech Digital Defense

  git clone https://github.com/trintechdigitaldefense/Sentinel.git
  cd Sentinel
  python3 setup.py

That is the only install step. Do NOT run restore_phase*.py.
After setup: python3 sentinel.py doctor
"""
from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
VERSION = "2.6.1"


def run(cmd: list) -> int:
    print(f"\n[*] {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


def step_assemble() -> None:
    asm = ROOT / "assemble_engine.py"
    if not asm.exists():
        if ENGINE.exists() and ENGINE.stat().st_size > 50000:
            print("[=] Using existing sentinel.py")
            return
        print("[!] Missing assemble_engine.py")
        sys.exit(1)
    if run([sys.executable, str(asm)]) != 0:
        print("[!] assemble failed")
        sys.exit(1)


def step_wire(name: str, script: str) -> None:
    p = ROOT / script
    if p.exists():
        run([sys.executable, str(p)])
    else:
        print(f"[=] {script} not present — skip")


def step_ui() -> None:
    fix = ROOT / "fix_ui.py"
    if fix.exists():
        run([sys.executable, str(fix)])
        return
    for script in ("wire_menu.py", "wire_menu_continuous.py", "set_banner_simple.py"):
        p = ROOT / script
        if p.exists():
            run([sys.executable, str(p)])


def step_clear_integrity() -> None:
    for p in {
        Path.home() / ".sentinel/data/self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data/self_integrity.json",
    }:
        if p.exists():
            try:
                p.unlink()
                print(f"[+] Cleared {p}")
            except Exception as e:
                print(f"[=] could not clear {p}: {e}")


def step_harden_defaults() -> None:
    """SMB-safe defaults: narrow subnets, WhatsApp off, quiet off."""
    cfg_path = Path.home() / ".sentinel/config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    data = Path.home() / ".sentinel/data"
    data.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cfg_path.parent, 0o700)
        os.chmod(data, 0o700)
    except Exception:
        pass

    c: dict = {}
    if cfg_path.exists():
        try:
            c = json.loads(cfg_path.read_text())
        except Exception:
            c = {}

    net = c.setdefault("network", {})
    nets = list(net.get("scan_subnets") or [])
    if not nets or any(str(s).endswith(("/8", "/12", "/11", "/10", "/9")) for s in nets):
        net["scan_subnets"] = [s for s in nets if not str(s).endswith(("/8", "/12", "/11", "/10", "/9"))] or [
            "192.168.1.0/24"
        ]
        print("[+] scan_subnets:", net["scan_subnets"])

    wa = c.setdefault("alerting", {}).setdefault("whatsapp", {})
    wa.setdefault("enabled", False)
    wa.setdefault("phone", "")
    wa.setdefault("apikey", "")

    q = c.setdefault("quiet_hours", {})
    q.setdefault("enabled", False)
    q.setdefault("start", "22:00")
    q.setdefault("end", "07:00")
    q.setdefault("allow_critical", True)

    c.setdefault("version", VERSION)
    cfg_path.write_text(json.dumps(c, indent=2))
    try:
        os.chmod(cfg_path, 0o600)
    except Exception:
        pass
    print(f"[+] Defaults written → {cfg_path}")


def step_doctor() -> None:
    doc = ROOT / "modules" / "doctor.py"
    if not doc.exists():
        print("[=] modules/doctor.py missing")
        return
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    print("\n[*] Running doctor…")
    subprocess.run(
        [sys.executable, "-c", "from modules.doctor import run_doctor; run_doctor(True)"],
        cwd=str(ROOT),
        env=env,
    )


def step_verify_banner() -> None:
    print("\n" + "=" * 56)
    print(f"  SENTINEL SETUP COMPLETE  (v{VERSION})")
    print("=" * 56)
    print(
        """
  Single install path is done. Daily use:

    python3 sentinel.py doctor      # readiness OK/WARN/FAIL
    python3 sentinel.py             # menu
    python3 sentinel.py integrity   # baseline once
    python3 sentinel.py deception   # canaries
    python3 sentinel.py service-install

  Config:  ~/.sentinel/config.json
  Do NOT run restore_phase*.py
"""
    )


def main() -> None:
    print("SENTINEL single install — TrinTech Digital Defense")
    print(f"Repo: {ROOT}")
    step_assemble()
    p4 = ROOT / "modules" / "phase4.py"
    if p4.exists() and p4.stat().st_size > 2000:
        try:
            py_compile.compile(str(p4), doraise=True)
            print(f"[=] modules/phase4.py OK ({p4.stat().st_size} bytes)")
        except Exception:
            print("[!] phase4.py invalid — git pull origin main")
    step_wire("phase4", "wire_phase4.py")
    step_ui()
    step_wire("phase5", "wire_phase5.py")
    step_wire("phase6", "wire_phase6.py")
    step_wire("phase7", "wire_phase7.py")
    step_wire("doctor", "wire_doctor.py")
    step_clear_integrity()
    step_harden_defaults()
    step_doctor()
    step_verify_banner()


if __name__ == "__main__":
    main()
