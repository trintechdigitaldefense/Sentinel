#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Bump setup.py to 3.3.0 and register Phase 9 apply scripts."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "setup.py"


def main() -> int:
    t = SETUP.read_text(encoding="utf-8")
    t2 = t.replace('VERSION = "3.2.1"', 'VERSION = "3.3.0"')
    t2 = t2.replace('VERSION = "3.2.0"', 'VERSION = "3.3.0"')
    if "apply_phase9" not in t2:
        insert = '''
def apply_phase9() -> None:
    for name in ("apply_phase9_bot.py", "apply_phase9_central.py"):
        script = ROOT / "scripts" / name
        if not script.exists():
            continue
        try:
            import runpy

            runpy.run_path(str(script), run_name="__main__")
        except SystemExit as e:
            if e.code not in (0, None):
                print(f"[!] {name} exit {e.code}")
        except Exception as e:
            print(f"[!] {name}: {e}")

'''
        if "def apply_dashboard_cases" in t2:
            t2 = t2.replace("def apply_dashboard_cases", insert + "def apply_dashboard_cases", 1)
        if "apply_dashboard_cases()" in t2 and "apply_phase9()" not in t2:
            t2 = t2.replace(
                "apply_dashboard_cases()",
                "apply_dashboard_cases()\n    apply_phase9()",
                1,
            )
    if t2 != t:
        SETUP.write_text(t2, encoding="utf-8")
        print("[+] setup.py Phase 9")
    else:
        print("[=] setup unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
