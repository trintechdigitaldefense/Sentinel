#!/usr/bin/env python3
"""Repair sentinel.py IndentationError after wire inject into while True:"""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py not found")
        sys.exit(1)

    src = ENGINE.read_text()
    ENGINE.with_suffix(".py.bak_indent").write_text(src)
    print("[+] backup: sentinel.py.bak_indent")

    lines = src.splitlines()
    changed = 0
    i = 0
    while i < len(lines):
        raw = lines[i]
        if re.match(r"^[ \t]*while True:\s*$", raw):
            base = len(raw) - len(raw.lstrip(" \t"))
            want = base + 4
            j = i + 1
            while j < len(lines):
                L = lines[j]
                if not L.strip():
                    j += 1
                    continue
                lead = len(L) - len(L.lstrip(" \t"))
                st = L.lstrip(" \t")
                if lead <= base:
                    lines[j] = (" " * want) + st
                    changed += 1
                    j += 1
                    continue
                break
            i = j
            continue
        i += 1

    ENGINE.write_text("\n".join(lines) + "\n")
    print(f"[+] adjusted {changed} under-indented lines")

    for attempt in range(50):
        try:
            py_compile.compile(str(ENGINE), doraise=True)
            print("[+] Syntax OK")
            print()
            print("Next:")
            print("  python3 sentinel.py doctor")
            print("  python3 sentinel.py dashboard-url")
            print("  python3 sentinel.py dashboard")
            return
        except py_compile.PyCompileError as e:
            m = re.search(r"line (\d+)", str(e))
            if not m:
                print(e)
                sys.exit(1)
            ln = int(m.group(1)) - 1
            lines = ENGINE.read_text().splitlines()
            if ln < 0 or ln >= len(lines):
                print(e)
                sys.exit(1)
            w = ln
            while w >= 0 and not re.match(r"^[ \t]*while True:\s*$", lines[w]):
                w -= 1
            if w < 0:
                st = lines[ln].lstrip(" \t")
                cur = len(lines[ln]) - len(st)
                lines[ln] = (" " * (cur + 4)) + st
            else:
                base = len(lines[w]) - len(lines[w].lstrip(" \t"))
                st = lines[ln].lstrip(" \t")
                lines[ln] = (" " * (base + 4)) + st
            ENGINE.write_text("\n".join(lines) + "\n")
            print(f"[*] fix pass {attempt+1}: line {ln+1}")
    print("[!] could not fully repair")
    sys.exit(1)


if __name__ == "__main__":
    main()
