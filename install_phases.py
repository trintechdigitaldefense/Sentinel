#!/usr/bin/env python3
"""Install all phase modules + wire scripts. Run from Sentinel repo root."""
import base64, json, zlib, pathlib, sys
root = pathlib.Path(__file__).resolve().parent
parts = []
for i in range(20):
    p = root / "modules" / f"install_blob_{i}.b64"
    if not p.exists():
        p = root / f"install_blob_{i}.b64"
    if not p.exists():
        break
    parts.append(p.read_text().strip())
if not parts:
    print("[!] missing install_blob_*.b64"); sys.exit(1)
blob = zlib.decompress(base64.b64decode("".join(parts)))
files = json.loads(blob.decode())
for rel, b64s in files.items():
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(base64.b64decode(b64s))
    print(f"[+] {rel} ({dest.stat().st_size} bytes)")
print("[+] Done. Run:")
print("  python3 assemble_engine.py")
print("  python3 wire_phase2.py && python3 wire_phase3.py && python3 wire_phase4.py")
print("  python3 sentinel.py phase4")
