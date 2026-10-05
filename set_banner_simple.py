#!/usr/bin/env python3
"""
Simple SENTINEL banner (no backslash art — no hybrid, no SyntaxWarning).

  python3 setup.py
  python3 wire_menu.py
  python3 wire_menu_continuous.py
  python3 set_banner_simple.py
"""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

BANNER_FN = '''
def print_banner():
    """Simple SENTINEL banner — no ASCII escapes."""
    w = 52
    line = "=" * w
    print()
    print(f"{C.CYAN}{C.BOLD}{line}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  SENTINEL{C.RESET}")
    try:
        ver = __version__
    except Exception:
        ver = "2.5.0"
    print(f"{C.BOLD}  v{ver}{C.RESET}")
    print(f"{C.GRAY}  TrinTech Digital Defense{C.RESET}")
    print(f"{C.GRAY}  Active Deception | Persistence Hunting | Line of Defense{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{line}{C.RESET}")
    print()
'''


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)

    src = ENGINE.read_text()

    while True:
        m = re.search(
            r"def print_banner\s*\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
            src,
            flags=re.DOTALL,
        )
        if not m:
            break
        src = src[: m.start()] + src[m.end() :]
        print("[+] Removed old print_banner")

    drop_prefixes = (
        "  _   _",
        " | \\ | |",
        " |  \\| |",
        " | . ` |",
        " | |\\  |",
        " |_| \\_|",
        " |_|  ____",
        " / ___||",
        " \\___ \\|",
        "  ___) |",
        " |____/|",
    )
    new_lines = []
    for line in src.splitlines(True):
        s = line.rstrip("\r\n")
        if any(s.startswith(p) for p in drop_prefixes):
            if "print(" in s or "def " in s or ("C." in s and "SENTINEL" in s):
                new_lines.append(line)
            else:
                continue
        else:
            new_lines.append(line)
    src = "".join(new_lines)

    idx = src.find("\ndef main(")
    if idx < 0:
        idx = src.find("def main(")
    if idx < 0:
        print("[!] def main not found")
        sys.exit(1)
    src = src[:idx] + "\n" + BANNER_FN + "\n" + src[idx:]

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Simple SENTINEL banner installed — syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax error: {e}")
        sys.exit(1)

    p = Path.home() / ".sentinel/data/self_integrity.json"
    if p.exists():
        p.unlink()
        print("[+] Integrity baseline cleared")

    print("""
Test:
  python3 sentinel.py start

You should see:

  ====================================================
    SENTINEL
    v2.5.0
    TrinTech Digital Defense
  ====================================================
""")


if __name__ == "__main__":
    main()
