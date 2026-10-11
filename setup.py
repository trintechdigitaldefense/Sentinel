#!/usr/bin/env python3
"""SENTINEL single install path — TrinTech Digital Defense v2.8"""
from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
VERSION = "2.8.0"


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
        net["scan_subnets"] = [s for s in nets if not str(s).endswith(("/8", "/12", "/11", "/10", "/9"))] or ["192.168.1.0/24"]
        print("[+] scan_subnets:", net["scan_subnets"])

    wa = c.setdefault("alerting", {}).setdefault("whatsapp", {})
    wa.setdefault("enabled", False)
    tg = c.setdefault("alerting", {}).setdefault("telegram", {})
    tg.setdefault("enabled", False)
    tg.setdefault("token", "")
    tg.setdefault("chat_id", "")

    q = c.setdefault("quiet_hours", {})
    q.setdefault("enabled", False)
    dm = c.setdefault("deadman", {})
    dm.setdefault("enabled", True)
    dm.setdefault("interval_sec", 300)
    dm.setdefault("timeout_sec", 600)

    portal = c.setdefault("portal", {})
    portal.setdefault("port", 8791)
    portal.setdefault("enabled", True)
    portal.setdefault("client_name", "Client")

    c.setdefault("usb_watch", False)
    det = c.setdefault("detection", {})
    det.setdefault("usb_watch", False)
    det.setdefault("dns_entropy_threshold", 3.8)

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
        return
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [sys.executable, "-c", "from modules.doctor import run_doctor; run_doctor(True)"],
        cwd=str(ROOT), env=env,
    )


def step_verify_banner() -> None:
    print("\n" + "=" * 56)
    print(f"  SENTINEL SETUP COMPLETE  (v{VERSION})")
    print("=" * 56)
    print("""
  python3 sentinel.py doctor
  python3 sentinel.py portal-url
  python3 sentinel.py portal
  python3 sentinel.py honey
  python3 sentinel.py crypto-status
  python3 sentinel.py suppress
  python3 sentinel.py suppress-add usb backup
  python3 sentinel.py drift-pdf
  python3 sentinel.py detect
  python3 sentinel.py service-install
""")


def main() -> None:
    print("SENTINEL single install — TrinTech Digital Defense")
    print(f"Repo: {ROOT}")
    step_assemble()
    p4 = ROOT / "modules" / "phase4.py"
    if p4.exists() and p4.stat().st_size > 2000:
        try:
            py_compile.compile(str(p4), doraise=True)
        except Exception:
            print("[!] phase4.py invalid")
    for name, script in [
        ("phase4", "wire_phase4.py"),
        ("ui", None),
        ("phase5", "wire_phase5.py"),
        ("phase6", "wire_phase6.py"),
        ("phase7", "wire_phase7.py"),
        ("doctor", "wire_doctor.py"),
        ("drift_deadman", "wire_drift_deadman.py"),
        ("revenue_tier2", "wire_revenue_tier2.py"),
        ("portal_harden", "wire_portal_harden.py"),
    ]:
        if name == "ui":
            step_ui()
        else:
            step_wire(name, script)
    step_clear_integrity()
    step_harden_defaults()
    step_doctor()
    step_verify_banner()


if __name__ == "__main__":
    main()
