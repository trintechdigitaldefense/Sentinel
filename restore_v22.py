#!/usr/bin/env python3
"""Restore Sentinel v2.2.0 Phase-1-wired engine. Run: python3 restore_v22.py"""
import zlib, base64, pathlib
# Full payload loaded from artifacts — if this stub is present, use local artifacts/sentinel.py
# Prefer downloading from release or copying modules + engine from operator machine.
STUB = True
if STUB:
    src = pathlib.Path(__file__).resolve().parent / "artifacts" / "sentinel.py"
    alt = pathlib.Path.home() / "Sentinel" / "sentinel.py"
    for p in (pathlib.Path("sentinel_v22_full.py"), src, alt):
        if p.exists() and p.stat().st_size > 50000:
            pathlib.Path("sentinel.py").write_bytes(p.read_bytes())
            print("[+] Restored sentinel.py from", p, "(", p.stat().st_size, "bytes)")
            raise SystemExit(0)
    print("[!] Full compressed payload omitted in this commit path.")
    print("[!] Copy your Phase-1-wired engine to sentinel.py or run from operator artifacts.")
    print("[!] Expected: modules/phase1.py present; version 2.2.0")
    raise SystemExit(1)
