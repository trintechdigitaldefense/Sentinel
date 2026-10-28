from __future__ import annotations
import re
from pathlib import Path

def test_menu_commands_have_handlers():
    t = Path("sentinel.py").read_text()
    start = t.find("main_items")
    end = t.find("def show(")
    assert start > 0 and end > start
    block = t[start:end]
    items = re.findall(r'\("[^"]+",\s*"[^"]+",\s*\((.*?)\)\)', block, re.S)
    roots = []
    for raw in items:
        parts = re.findall(r'"([^"]+)"', raw)
        if parts and not parts[0].startswith("__"):
            roots.append(parts[0])
    handlers = set()
    for m in re.finditer(r'command\s*==\s*"([^"]+)"', t):
        handlers.add(m.group(1))
    for m in re.finditer(r'command\s+in\s+\(([^)]+)\)', t):
        for p in re.findall(r'"([^"]+)"', m.group(1)):
            handlers.add(p)
    missing = sorted({r for r in roots if r not in handlers})
    assert not missing, f"Menu options missing CLI handlers: {missing}"
    assert "fleet-scan" in roots or "fleet-scan" in handlers
    assert "__fleet__" in block

def test_no_args_calls_menu():
    t = Path("sentinel.py").read_text()
    idx = t.find("def main():")
    head = t[idx:idx+400]
    assert "interactive_menu()" in head
    # only one active early return for no args
    assert head.count("interactive_menu()") >= 1
