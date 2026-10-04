#!/usr/bin/env python3
"""Sentinel Phase 2 — Deception Layer (loads phase2_a + phase2_b)."""
from pathlib import Path
_d = Path(__file__).resolve().parent
_a = _d / "phase2_a.py"
_b = _d / "phase2_b.py"
if not (_a.exists() and _b.exists()):
    raise ImportError("Missing modules/phase2_a.py or phase2_b.py — run git pull")
exec(compile(_a.read_text() + "\n" + _b.read_text(), str(_d / "phase2.py"), "exec"))
