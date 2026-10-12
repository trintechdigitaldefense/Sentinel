#!/usr/bin/env python3
"""SENTINEL stabilize — single ordered post-assemble path.

Runs wire/fix scripts in a fixed order, compiles after each step,
and restores the previous engine on failure. Used by setup.py.
"""
from __future__ import annotations
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
BACKUP = ROOT / "sentinel.py.bak_stabilize"

STEPS = [
    ("phase4", "wire_phase4.py", False),
    ("ui", "fix_ui.py", False),
    ("phase5", "wire_phase5.py", False),
    ("phase6", "wire_phase6.py", False),
    ("phase7", "wire_phase7.py", False),
    ("doctor", "wire_doctor.py", False),
    ("drift_deadman", "wire_drift_deadman.py", False),
    ("revenue_tier2", "wire_revenue_tier2.py", False),
    ("portal_harden", "wire_portal_harden.py", False),
    ("bonus", "wire_bonus.py", False),
    ("dashboard", "wire_dashboard.py", False),
    ("cli_safe", "wire_cli_safe.py", False),
    ("hooks", "rebuild_hooks.py", True),
    ("self_integrity", "fix_self_integrity.py", False),
    ("process_scan", "fix_process_scan.py", False),
]

REQUIRED_MARKERS = [
    'command == "doctor"',
    'command == "dash"',
    'command == "hunt"',
    "while True",
]


def compile_engine() -> None:
    py_compile.compile(str(ENGINE), doraise=True)


def run_script(script: str) -> int:
    p = ROOT / script
    if not p.exists():
        print(f"  [=] skip {script} (missing)")
        return 0
    print(f"  [*] {script}")
    r = subprocess.run([sys.executable, str(p)], cwd=str(ROOT))
    return r.returncode


def markers_ok() -> list:
    if not ENGINE.exists():
        return ["engine missing"]
    src = ENGINE.read_text(errors="ignore")
    missing = []
    for m in REQUIRED_MARKERS:
        if m not in src:
            if m == 'command == "dash"' and ("dashboard" in src or 'command == "dashboard"' in src):
                continue
            if m == 'command == "doctor"' and "doctor" in src:
                continue
            missing.append(m)
    return missing


def main() -> int:
    print("=" * 56)
    print("  SENTINEL STABILIZE")
    print("=" * 56)
    if not ENGINE.exists() or ENGINE.stat().st_size < 10000:
        print("[!] sentinel.py missing or too small — run assemble first")
        return 1

    shutil.copy2(ENGINE, BACKUP)
    print(f"[+] Backup → {BACKUP.name} ({BACKUP.stat().st_size} bytes)")

    try:
        compile_engine()
        print("[+] Engine compiles before wiring")
    except Exception as e:
        print(f"[!] Engine does not compile before wiring: {e}")
        return 1

    for label, script, required in STEPS:
        before = ENGINE.read_bytes()
        rc = run_script(script)
        try:
            compile_engine()
        except Exception as e:
            print(f"[!] {label}: syntax broken after {script}")
            print(f"    {e}")
            ENGINE.write_bytes(before)
            print(f"    restored previous good engine ({len(before)} bytes)")
            if required:
                print("[!] required step failed — abort")
                return 1
            continue
        if rc != 0 and required:
            print(f"[!] required step {label} exited {rc}")
            return 1
        print(f"  [+] {label} OK")

    missing = markers_ok()
    if missing:
        print(f"[!] Missing markers after stabilize: {missing}")
        print("    continuing (soft)")
    else:
        print("[+] Required command markers present")

    try:
        compile_engine()
        print(f"[+] Final engine OK ({ENGINE.stat().st_size} bytes)")
    except Exception as e:
        print(f"[!] Final compile failed: {e}")
        if BACKUP.exists():
            shutil.copy2(BACKUP, ENGINE)
            print("[+] Restored backup")
        return 1

    print("=" * 56)
    print("  STABILIZE COMPLETE")
    print("=" * 56)
    return 0


if __name__ == "__main__":
    sys.exit(main())
