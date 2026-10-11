#!/usr/bin/env python3
"""SENTINEL fix_hunt_loop — alias of rebuild_hooks (restore hunt + hooks)."""
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).resolve().parent / "rebuild_hooks.py"), run_name="__main__")
