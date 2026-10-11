#!/usr/bin/env python3
"""Rebuild hunt-loop hooks with correct indentation."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

HOOK_MARKERS = [
    "heartbeat_from_hunt", "emit_heartbeat as _dm_emit",
    "from modules.deadman import emit_heartbeat",
    "from modules.phase5 import heartbeat_from_hunt",
    "check_fleet", "usb_watch", "lateral", "dns_watch",
    "persistence_hunt", "honeyauth", "ransomware_tripwire",
    "device_radar", "rules_engine",
]


def strip_broken_hook_blocks(src: str) -> str:
    lines = src.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^[ \t]*try:\s*$", line):
            block = [line]
            j = i + 1
            while j < len(lines):
                block.append(lines[j])
                if re.match(r"^[ \t]*except\b", lines[j]) or re.match(r"^[ \t]*finally\b", lines[j]):
                    j += 1
                    while j < len(lines):
                        if lines[j].strip() == "":
                            block.append(lines[j]); j += 1; continue
                        try_indent = len(line) - len(line.lstrip(" \t"))
                        lead = len(lines[j]) - len(lines[j].lstrip(" \t"))
                        if lead <= try_indent and not lines[j].lstrip().startswith(("except", "finally", "else")):
                            break
                        if re.match(r"^[ \t]*except\b", lines[j]) or re.match(r"^[ \t]*else:", lines[j]):
                            block.append(lines[j]); j += 1; continue
                        block.append(lines[j]); j += 1
                    break
                j += 1
                if j - i > 40:
                    break
            blob = "".join(block)
            if any(m in blob for m in HOOK_MARKERS):
                i = j
                continue
        out.append(line)
        i += 1
    return "".join(out)


def find_hunt_while(src: str) -> int:
    idx = src.find("Persistence hunting")
    if idx < 0:
        idx = src.find("persistence_hunt(config")
    search_from = 0
    best = -1
    while True:
        wt = src.find("while True:", search_from)
        if wt < 0:
            break
        window = src[wt : wt + 300]
        if "persistence_hunt" in window or "process_scan" in window:
            best = wt
            if "persistence_hunt" in window:
                return wt
        search_from = wt + 1
    return best


def make_hooks(body_indent: str) -> str:
    bi = body_indent
    inner = body_indent + "    "
    return f"""
{bi}# --- Sentinel hooks (auto) ---
{bi}try:
{inner}from modules.phase5 import heartbeat_from_hunt
{inner}heartbeat_from_hunt()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.deadman import emit_heartbeat as _dm_emit, check_fleet as _dm_fleet
{inner}_dm_emit("hunt")
{inner}_dm_fleet()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.usb_watch import check as _usb_check
{inner}_usb_check()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.lateral import check as _lat_check
{inner}_lat_check()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.dns_watch import check as _dns_check
{inner}_dns_check()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.device_radar import check as _radar_check
{inner}_radar_check()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.ransomware_tripwire import check as _tw_check
{inner}_tw_check()
{bi}except Exception:
{inner}pass
{bi}try:
{inner}from modules.honeyauth import check as _honey_check
{inner}_honey_check()
{bi}except Exception:
{inner}pass
{bi}# --- end hooks ---
"""


def fix_empty_elifs():
    lines = ENGINE.read_text().splitlines()
    fixed_empty = 0
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        stripped = line.lstrip()
        if stripped.startswith("elif ") and stripped.rstrip().endswith(":"):
            ind = len(line) - len(stripped)
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                out.append(lines[j])
                j += 1
            if j >= len(lines) or (
                lines[j].lstrip().startswith(("elif ", "else:", "def ", "class "))
                and (len(lines[j]) - len(lines[j].lstrip())) <= ind
            ):
                out.append(" " * (ind + 4) + "pass  # placeholder")
                fixed_empty += 1
                i = j
                continue
            i = j
            continue
        i += 1
    if fixed_empty:
        ENGINE.write_text("\n".join(out) + "\n")
        print(f"[+] filled {fixed_empty} empty elif bodies with pass")


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py missing — run assemble/setup first")
        sys.exit(1)

    src = ENGINE.read_text()
    ENGINE.with_suffix(".py.bak_hooks").write_text(src)
    print("[+] backup: sentinel.py.bak_hooks")

    src = strip_broken_hook_blocks(src)

    wt = find_hunt_while(src)
    if wt < 0:
        print("[!] could not find hunt while True:")
        ENGINE.write_text(src)
        fix_empty_elifs()
        try:
            py_compile.compile(str(ENGINE), doraise=True)
            print("[+] Syntax OK (no hunt while)")
            return
        except Exception as e:
            print("[!]", e)
            sys.exit(1)

    line_start = src.rfind("\n", 0, wt) + 1
    while_line = src[line_start : src.find("\n", wt)]
    while_indent = while_line[: len(while_line) - len(while_line.lstrip(" \t"))]
    body_indent = while_indent + "    "
    print(f"[+] while True indent={len(while_indent)} spaces -> body={len(body_indent)}")

    hooks = make_hooks(body_indent)
    end = wt + len("while True:")
    if "Sentinel hooks (auto)" in src:
        print("[=] hooks marker already present — stripping first")
        src = re.sub(
            r"[ \t]*# --- Sentinel hooks \(auto\) ---.*?# --- end hooks ---\n?",
            "",
            src,
            flags=re.S,
        )
        wt = find_hunt_while(src)
        end = wt + len("while True:")

    src = src[:end] + hooks + src[end:]
    ENGINE.write_text(src)
    fix_empty_elifs()

    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK — hooks rebuilt")
    except Exception as e:
        print("[!] Still broken:", e)
        lines = ENGINE.read_text().splitlines()
        m = re.search(r"line (\d+)", str(e))
        if m:
            ln = int(m.group(1))
            for i in range(max(0, ln - 5), min(len(lines), ln + 8)):
                print(f"{i+1}: {lines[i]}")
        sys.exit(1)

    print()
    print("Next:")
    print("  python3 sentinel.py doctor")
    print("  python3 sentinel.py dashboard-url")
    print("  python3 sentinel.py dashboard")


if __name__ == "__main__":
    main()
