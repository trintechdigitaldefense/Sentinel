#!/usr/bin/env python3
"""One-shot: repair elif command == integrity missing colon."""
from pathlib import Path
import py_compile
import re

p = Path(__file__).resolve().parent / "sentinel.py"
src = p.read_text()
src2 = re.sub(
    r'(elif command == "integrity")\s*$',
    r'\1:',
    src,
    flags=re.M,
)
src2 = re.sub(r'\n[ \t]*:[ \t]*\n', '\n', src2)
p.write_text(src2)
try:
    py_compile.compile(str(p), doraise=True)
    print("[+] integrity colon fixed — Syntax OK")
except Exception as e:
    print("[!]", e)
    lines = p.read_text().splitlines()
    m = re.search(r"line (\d+)", str(e))
    if m:
        ln = int(m.group(1))
        for i in range(max(0, ln - 3), min(len(lines), ln + 5)):
            print(f"{i+1}: {repr(lines[i])}")
