#!/usr/bin/env python3
"""Restore Phase 4 — Hard to Copy"""
import base64, zlib, pathlib
root = pathlib.Path(__file__).resolve().parent
mod = root / "modules"
mod.mkdir(parents=True, exist_ok=True)
def piece(name):
    for p in (mod / name, root / name):
        if p.exists():
            return p.read_text().strip()
    raise FileNotFoundError(name)
parts = []
for letter in "abcdefgh":
    try:
        parts.append(piece(f"p4{letter}.b64"))
    except FileNotFoundError:
        break
p4 = "".join(parts)
w4 = piece("w4.b64")
(mod / "phase4.py").write_bytes(zlib.decompress(base64.b64decode(p4)))
(root / "wire_phase4.py").write_bytes(zlib.decompress(base64.b64decode(w4)))
print("[+] modules/phase4.py", (mod/"phase4.py").stat().st_size)
print("[+] wire_phase4.py", (root/"wire_phase4.py").stat().st_size)
print("[+] Next: python3 wire_phase4.py")
