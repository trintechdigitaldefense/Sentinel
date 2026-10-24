#!/usr/bin/env python3
import os, sys, tempfile, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SENTINEL_DIR", tempfile.mkdtemp(prefix="sentinel-fw-"))
from modules import firewall as fw
print("[*] version", fw.VERSION, "backend", fw.backend())
print(json.dumps(fw.status(), indent=2)[:600])
assert fw.block_ip("203.0.113.10", confirm=False).get("dry_run")
assert fw.block_ip("203.0.113.0/24", confirm=False).get("kind") == "cidr"
assert fw.apply_profile("lab_lockdown", confirm=False).get("dry_run")
assert fw.apply_managed(confirm=False).get("dry_run")
print(json.dumps(fw.doctor(), indent=2))
print("[+] firewall 13.1 smoke PASS")
