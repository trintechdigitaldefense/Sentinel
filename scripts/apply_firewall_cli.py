#!/usr/bin/env python3
"""Wire firewall CLI into sentinel.py and setup hooks."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sent = ROOT / "sentinel.py"
text = sent.read_text(encoding="utf-8", errors="replace")
changed = False
if 'command in ("firewall", "fw")' not in text:
    needle = '    if command == "start":'
    block = '''    # phase13_firewall_cli
    if command in ("firewall", "fw"):
        from modules import firewall as fw_mod
        raise SystemExit(fw_mod.cli(args if args else ["status"]))

    if command == "start":'''
    if needle in text:
        text = text.replace(needle, block, 1)
        changed = True
        print("wired firewall command")
    else:
        print("anchor missing for command")
else:
    print("firewall command already present")

if "firewall status" not in text:
    old = 'print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}unblock <ip>{C.RESET}         Unblock an IP")'
    if old in text:
        text = text.replace(
            old,
            old + '\n        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}firewall status{C.RESET}     Host firewall (nft/iptables)")',
            1,
        )
        changed = True

if changed:
    sent.write_text(text)
    print("sentinel.py updated")
else:
    print("no sentinel.py text changes needed")
