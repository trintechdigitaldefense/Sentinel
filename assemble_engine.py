#!/usr/bin/env python3
"""Assemble and restore Sentinel v2.2.0 Phase-1-wired engine from chunks."""
import base64, zlib, pathlib
root = pathlib.Path(__file__).resolve().parent
parts = []
i = 0
while True:
    p = root / "engine_chunks" / f"part_{i}.b64"
    if not p.exists():
        break
    parts.append(p.read_text().strip())
    i += 1
if not parts:
    raise SystemExit("No engine_chunks/part_*.b64 found")
data = "".join(parts)
out = root / "sentinel.py"
out.write_bytes(zlib.decompress(base64.b64decode(data)))
print(f"[+] Restored sentinel.py v2.2.0 ({out.stat().st_size} bytes)")
print("[+] Phase 1 wired: quarantine, quiet, beacons, onboard")
