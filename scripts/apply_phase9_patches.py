#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Apply Phase 9 bot + central patches (or fall back to inline injectors)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _patch(target: Path, patch_file: Path) -> bool:
    if not patch_file.exists() or not target.exists():
        return False
    r = subprocess.run(
        ["patch", "-N", "-r", "-", "-i", str(patch_file), str(target)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    print(r.stdout or r.stderr or f"patch {patch_file.name} exit {r.returncode}")
    return r.returncode in (0, 1)  # 1 = already applied


def main() -> int:
    bot = ROOT / "modules" / "bot.py"
    srv = ROOT / "sentinel_central" / "server.py"
    _patch(bot, ROOT / "patches" / "phase9_bot.patch")
    # Prefer dedicated injectors if present
    for name in ("apply_phase9_bot.py", "apply_phase9_central.py"):
        script = ROOT / "scripts" / name
        if script.exists():
            try:
                import runpy

                runpy.run_path(str(script), run_name="__main__")
            except SystemExit as e:
                if e.code not in (0, None):
                    print(f"[!] {name} {e.code}")
            except Exception as e:
                print(f"[!] {name}: {e}")
    # setup bump
    setup = ROOT / "scripts" / "apply_setup_phase9.py"
    if setup.exists():
        try:
            import runpy

            runpy.run_path(str(setup), run_name="__main__")
        except Exception as e:
            print(f"[!] setup: {e}")
    print("[+] Phase 9 patches attempted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
