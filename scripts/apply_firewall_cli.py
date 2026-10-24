#!/usr/bin/env python3
"""Wire firewall CLI into sentinel.py."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sent = ROOT / "sentinel.py"
text = sent.read_text(encoding="utf-8", errors="replace")
if 'command in ("firewall", "fw")' in text:
    print("firewall CLI already present")
    raise SystemExit(0)
needle = '    if command == "start":'
block = '''    # phase13_firewall_cli
    if command in ("firewall", "fw"):
        from modules import firewall as fw_mod
        raise SystemExit(fw_mod.cli(args if args else ["status"]))

    if command == "start":'''
if needle not in text:
    print("anchor missing")
    raise SystemExit(1)
sent.write_text(text.replace(needle, block, 1))
print("wired firewall into sentinel.py")
