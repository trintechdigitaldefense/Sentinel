#!/usr/bin/env python3
"""
Sentinel one-command setup — TrinTech Digital Defense

  cd ~/Sentinel
  python3 setup.py

Does everything: assemble engine → ensure Phase 4 module → wire CLI →
refresh help text → clear false integrity alerts → print status.
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


def run(cmd: list) -> int:
    print(f"\n[*] {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=str(ROOT))
    return r.returncode


def step_assemble() -> None:
    asm = ROOT / "assemble_engine.py"
    if not asm.exists():
        if ENGINE.exists() and ENGINE.stat().st_size > 50000:
            print("[=] assemble_engine.py missing — using existing sentinel.py")
            return
        print("[!] Missing assemble_engine.py and no usable sentinel.py")
        sys.exit(1)
    if run([sys.executable, str(asm)]) != 0:
        print("[!] assemble failed")
        sys.exit(1)


def step_phase4_module() -> None:
    PHASE4.parent.mkdir(parents=True, exist_ok=True)
    if PHASE4.exists() and PHASE4.stat().st_size > 2000:
        try:
            py_compile.compile(str(PHASE4), doraise=True)
            print(f"[=] modules/phase4.py OK ({PHASE4.stat().st_size} bytes)")
            return
        except Exception:
            print("[*] phase4.py present but invalid — will rely on git pull")
    print("[!] modules/phase4.py missing or broken.")
    print("    Run:  git pull origin main")
    print("    Then: python3 setup.py")


def step_wire_phase4() -> None:
    if not WIRE4.exists():
        print("[!] wire_phase4.py missing — git pull origin main")
        sys.exit(1)
    if run([sys.executable, str(WIRE4)]) != 0:
        print("[!] wire_phase4 failed")
        sys.exit(1)


def step_help_banner() -> None:
    if not ENGINE.exists():
        return
    src = ENGINE.read_text()
    if "PHASE 4:" in src and "sentinel baseline" in src:
        print("[=] Help already lists Phase 4")
        return
    needle = 'print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}phase1{C.RESET}'
    if needle in src and "phase4" not in src[src.find(needle):src.find(needle)+800]:
        inject = (
            'print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}phase4{C.RESET}                 Phase 4 self-check")\n'
            '        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}baseline{C.RESET}               Behavioral baseline")\n'
            '        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}caribbean{C.RESET}              Caribbean threat pack")\n'
            '        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}playbook{C.RESET}               Response playbooks")\n'
            '        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}evidence{C.RESET}               Evidence pack")\n'
            '        ' + needle
        )
        src = src.replace(needle, inject, 1)
        ENGINE.write_text(src)
        print("[+] Help text updated with Phase 4")
        return
    if "PHASE 1:" in src and "PHASE 4:" not in src:
        src = src.replace(
            "PHASE 1:",
            "PHASE 4:\n  sentinel phase4 / baseline / caribbean / playbook / evidence / offline\n\nPHASE 1:",
            1,
        )
        ENGINE.write_text(src)
        print("[+] Help note for Phase 4 added")
    else:
        print("[=] Help patch skipped — Phase 4 commands still work")


def step_clear_integrity() -> None:
    import os
    paths = {
        Path.home() / ".sentinel" / "data" / "self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data" / "self_integrity.json",
    }
    for p in paths:
        if p.exists():
            p.unlink()
            print(f"[+] Cleared {p}")


def step_verify() -> None:
    print("\n" + "=" * 50)
    print("  SENTINEL SETUP COMPLETE")
    print("=" * 50)
    r = subprocess.run(
        [sys.executable, str(ENGINE), "phase4"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0 and "behavioral_enabled" in out:
        print("[+] phase4 works")
    else:
        print("[!] phase4 check failed:")
        print(out[-500:])
        print("\nTry: git pull && python3 setup.py")
        return
    print("""
Daily use (no more restore scripts):

  python3 sentinel.py start
  python3 sentinel.py hunt
  python3 sentinel.py baseline
  python3 sentinel.py baseline check
  python3 sentinel.py caribbean
  python3 sentinel.py playbook REVERSE_SHELL
  python3 sentinel.py evidence --hours 24
  python3 sentinel.py phase4

If you re-run assemble_engine.py, run setup again:

  python3 setup.py

Do NOT run restore_phase2/3/4.py (broken packs).
""")


def main() -> None:
    print("Sentinel setup — TrinTech Digital Defense")
    print(f"Repo: {ROOT}")
    step_assemble()
    step_phase4_module()
    step_wire_phase4()
    step_help_banner()
    step_clear_integrity()
    step_verify()


if __name__ == "__main__":
    main()
