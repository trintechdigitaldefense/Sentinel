#!/usr/bin/env python3
import base64,zlib,pathlib
r=pathlib.Path(__file__).resolve().parent
m=r/"modules"; m.mkdir(parents=True,exist_ok=True)
d=(m/"p2c1.b64").read_text().strip()+(m/"p2c2.b64").read_text().strip()
(m/"phase2.py").write_bytes(zlib.decompress(base64.b64decode(d)))
print("[+] modules/phase2.py", (m/"phase2.py").stat().st_size)
print("[+] Phase 2: Mirage, adaptive decoys, scoring, process canaries, timeline")
print('[+] Test: python3 -c "from modules.phase2 import mirage_deploy; print(\'OK\')"')
