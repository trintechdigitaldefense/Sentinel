"""Ensure main menu numbers are sequential and every CLI target exists."""
from pathlib import Path
import re
import ast

def _extract_menu_block(name: str) -> list:
    t = Path("sentinel.py").read_text()
    m = re.search(rf"{name}\s*=\s*\[(.*?)\]\n\n", t, re.S)
    assert m, name
    # crude parse of ("n", "label", (...))
    entries = re.findall(
        r'\("([^"]+)",\s*"([^"]*)",\s*(\([^)]*\))',
        m.group(1),
    )
    return entries

def test_main_menu_sequential():
    entries = _extract_menu_block("main_items")
    nums = [e[0] for e in entries if e[0] != "0"]
    assert nums == [str(i) for i in range(1, len(nums) + 1)], nums

def test_all_menus_have_exit_or_back():
    for name in ("main_items", "detect_items", "firewall_items", "ssh_items", "ops_items", "fleet_items", "p4_items"):
        entries = _extract_menu_block(name)
        args = [e[2] for e in entries]
        joined = " ".join(args)
        assert "__exit__" in joined or "__back__" in joined, name

def test_menu_cli_targets_known():
    t = Path("sentinel.py").read_text()
    # collect command tokens from elif command
    known = set(re.findall(r'command == "([^"]+)"', t))
    known |= set(re.findall(r'command in \(([^)]+)\)', t))
    flat = set()
    for chunk in list(known):
        if '"' in chunk:
            flat |= set(re.findall(r'"([^"]+)"', chunk))
        else:
            flat.add(chunk)
    special = {
        "__continuous__", "__exit__", "__back__", "__detect__", "__firewall__",
        "__ops__", "__fleet__", "__phase4__", "__ssh__", "__fw_protect__",
        "__fw_defend__", "__sim_all__",
    }
    for name in ("main_items", "detect_items", "firewall_items", "ssh_items", "ops_items", "fleet_items", "p4_items"):
        for num, label, args in _extract_menu_block(name):
            toks = re.findall(r'"([^"]+)"', args)
            if not toks:
                continue
            head = toks[0]
            if head in special:
                continue
            assert head in flat, f"{name} option {num} wires unknown command '{head}'"
