#!/usr/bin/env python3
"""Restore Phase 3 — WhatsApp default +1-868-362-0679"""
import base64, zlib, pathlib
root = pathlib.Path(__file__).resolve().parent
mod = root / "modules"
mod.mkdir(parents=True, exist_ok=True)
def piece(name):
    p = mod / name
    if not p.exists():
        p = root / name
    return p.read_text().strip()
p3 = piece("p3a.b64") + piece("p3b.b64") + piece("p3c.b64")
w3 = piece("w3.b64")
(mod / "phase3.py").write_bytes(zlib.decompress(base64.b64decode(p3)))
(root / "wire_phase3.py").write_bytes(zlib.decompress(base64.b64decode(w3)))
print("[+] modules/phase3.py", (mod/"phase3.py").stat().st_size)
print("[+] wire_phase3.py", (root/"wire_phase3.py").stat().st_size)
print("[+] WhatsApp default: +1-868-362-0679")
print("[+] Next: python3 wire_phase3.py")
