#!/usr/bin/env python3
"""Assemble Sentinel v2.2.0 Phase-1-wired engine from chunks."""
import base64, zlib, pathlib, sys

root = pathlib.Path(__file__).resolve().parent
parts = []
i = 0
while True:
    full = root / "engine_chunks" / f"part_{i}.b64"
    a = root / "engine_chunks" / f"part_{i}a.b64"
    b = root / "engine_chunks" / f"part_{i}b.b64"

    chunk = None
    # Prefer a+b halves when both exist and look complete (~4000 each)
    if a.exists() and b.exists():
        ca, cb = a.read_text().strip(), b.read_text().strip()
        if len(ca) >= 3500 and len(cb) >= 3500:
            chunk = ca + cb
    # Or a complete full part (not a stub)
    if chunk is None and full.exists():
        cf = full.read_text().strip()
        if len(cf) >= 3500:
            chunk = cf
    # Last part may be shorter (part_3 ~4440)
    if chunk is None and full.exists():
        cf = full.read_text().strip()
        if len(cf) >= 1000 and i >= 3:
            chunk = cf
    if chunk is None and a.exists() and b.exists():
        chunk = a.read_text().strip() + b.read_text().strip()

    if chunk is None:
        break
    parts.append(chunk)
    print(f"  [+] part_{i}: {len(chunk)} chars")
    i += 1

if len(parts) < 4:
    print(f"[!] Expected 4 parts, got {len(parts)}. Chunks incomplete.")
    sys.exit(1)

data = "".join(parts)
try:
    raw = zlib.decompress(base64.b64decode(data))
except Exception as e:
    print("[!] Decompress failed:", e)
    sys.exit(1)

out = root / "sentinel.py"
out.write_bytes(raw)
print(f"[+] Restored sentinel.py v2.2.0 ({out.stat().st_size} bytes)")
print("[+] Phase 1 wired: quarantine, quiet, beacons, onboard")
print("[+] Next: python3 sentinel.py phase1")
