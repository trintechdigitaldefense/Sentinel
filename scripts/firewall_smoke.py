#!/usr/bin/env python3
import os, sys, tempfile, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SENTINEL_DIR", tempfile.mkdtemp(prefix="sentinel-fw-"))
from modules import firewall as fw
print("[*] backend", fw.backend())
print(json.dumps(fw.status(), indent=2)[:800])
r = fw.block_ip("203.0.113.10", confirm=False)
assert r.get("dry_run")
print("[+] dry-run block ok")
print("[+] profiles", list(fw.list_profiles()["profiles"]))
print(json.dumps(fw.doctor(), indent=2))
print("[+] firewall smoke PASS")
