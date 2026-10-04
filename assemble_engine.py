#!/usr/bin/env python3
"""Assemble Sentinel v2.2.0 Phase-1-wired engine."""
import base64, zlib, pathlib
root = pathlib.Path(__file__).resolve().parent
parts = []
i = 0
while True:
    full = root / "engine_chunks" / f"part_{i}.b64"
    a = root / "engine_chunks" / f"part_{i}a.b64"
    b = root / "engine_chunks" / f"part_{i}b.b64"
    if full.exists():
        parts.append(full.read_text().strip())
    elif a.exists() and b.exists():
        parts.append(a.read_text().strip() + b.read_text().strip())
    else:
        break
    i += 1
if not parts:
    raise SystemExit("No engine_chunks found")
data = "".join(parts)
out = root / "sentinel.py"
out.write_bytes(zlib.decompress(base64.b64decode(data)))
print(f"[+] Restored sentinel.py v2.2.0 ({out.stat().st_size} bytes)")
print("[+] Phase 1 wired: quarantine, quiet, beacons, onboard")
