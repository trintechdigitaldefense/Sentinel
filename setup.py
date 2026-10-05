#!/usr/bin/env python3
"""
Sentinel one-command setup — TrinTech Digital Defense

  git clone https://github.com/trintechdigitaldefense/Sentinel.git
  cd Sentinel
  python3 setup.py
"""
from __future__ import annotations

import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
PHASE4 = ROOT / "modules" / "phase4.py"
WIRE4 = ROOT / "wire_phase4.py"
FIX_UI = ROOT / "fix_ui.py"


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


def step_phase4() -> None:
    PHASE4.parent.mkdir(parents=True, exist_ok=True)
    if PHASE4.exists() and PHASE4.stat().st_size > 2000:
        try:
            py_compile.compile(str(PHASE4), doraise=True)
            print(f"[=] modules/phase4.py OK ({PHASE4.stat().st_size} bytes)")
        except Exception:
            print("[!] phase4.py invalid — git pull origin main")
    else:
        print("[!] modules/phase4.py missing — git pull origin main")
    if WIRE4.exists():
        run([sys.executable, str(WIRE4)])
    else:
        print("[!] wire_phase4.py missing")


def step_ui() -> None:
    if FIX_UI.exists():
        run([sys.executable, str(FIX_UI)])
    else:
        for script in ("wire_menu.py", "wire_menu_continuous.py", "set_banner_simple.py"):
            p = ROOT / script
            if p.exists():
                run([sys.executable, str(p)])


def step_clear_integrity() -> None:
    import os
    for p in {
        Path.home() / ".sentinel/data/self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data/self_integrity.json",
    }:
        if p.exists():
            p.unlink()
            print(f"[+] Cleared {p}")


def step_default_subnet() -> None:
    import json
    cfg = Path.home() / ".sentinel/config.json"
    if not cfg.exists():
        return
    try:
        c = json.loads(cfg.read_text())
        nets = c.get("network", {}).get("scan_subnets", [])
        if any(s.endswith(("/8", "/12", "/11", "/10")) for s in nets):
            c.setdefault("network", {})["scan_subnets"] = [
                s for s in nets if not s.endswith(("/8", "/12", "/11", "/10"))
            ] or ["192.168.1.0/24"]
            cfg.write_text(json.dumps(c, indent=2))
            print("[+] Restricted scan_subnets:", c["network"]["scan_subnets"])
    except Exception as e:
        print(f"[=] subnet tweak skipped: {e}")


def step_verify() -> None:
    print("\n" + "=" * 50)
    print("  SENTINEL SETUP COMPLETE")
    print("=" * 50)
    r = subprocess.run(
        [sys.executable, str(ENGINE), "phase4"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=90,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "behavioral_enabled" in out or r.returncode == 0:
        print("[+] phase4 OK")
    else:
        print("[!] phase4 check weak — still try menu")
        print(out[-400:])

    print("""
========================================
  HOW TO USE
========================================

  python3 sentinel.py              # numbered menu
  python3 sentinel.py start        # one-shot scan + decoys
  python3 sentinel.py hunt         # continuous protection

First-time client host:
  1. python3 sentinel.py           → menu → 5 (integrity)
  2. menu → 1  (continuous protection)  leave running
  3. menu → 8  Phase 4 as needed

Config:  ~/.sentinel/config.json
Do NOT run restore_phase*.py
""")


def main() -> None:
    print("Sentinel setup — TrinTech Digital Defense")
    print(f"Repo: {ROOT}")
    step_assemble()
    step_phase4()
    step_ui()
    step_clear_integrity()
    step_default_subnet()
    step_verify()


if __name__ == "__main__":
    main()
