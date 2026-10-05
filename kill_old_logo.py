#!/usr/bin/env python3
"""
Remove hardcoded old logo from sentinel.py and force print_banner() everywhere.
Run AFTER: setup.py + wire_menu.py + wire_menu_continuous.py + set_banner_simple.py
"""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

VARIANTS = [
    """  _   _      _   _        _     _______ _
 | \\ | |    | \\ | |      | |   |__   __(_)
 |  \\| | ___|  \\| | __ _ | |  __ _| |__  _ _ __ ___
 | . ` |/ _ \\ . ` |/ _` || | / _` | '_ \\| | '_ ` _ \\
 | |\\  |  __/ |\\  | (_| || || (_| | |_) | | | | | | |
 |_| \\_|\\___|_| \\_|\\__,_||_| \\__,_|_.__/|_|_| |_| |_|""",
    """  _   _      _   _        _     _______ _
 | \\ | |    | \\ | |      | |   |__   __(_)
 |  \\| | ___|  \\| | __ _ | |  __ _| |__  _ _ __ ___
 | |\\  |  __/ |\\  | (_| || || (_| | |_) | | | | | | |
 |_| \\_|\\___|_| \\_|\\__,_||_| \\__,_|_.__/|_|_| |_| |_|""",
]


def main():
    src = ENGINE.read_text()
    removed = 0

    for old in VARIANTS:
        if old in src:
            src = src.replace(old, "")
            removed += 1
            print("[+] Removed exact logo variant")

    pattern = re.compile(
        r"(?:^|\n)(  _   _\s+_   _[^\n]*\n(?: \|[^\n]*\n){3,6})",
        re.MULTILINE,
    )
    src2, n = pattern.subn("\n", src)
    if n:
        src = src2
        print(f"[+] Regex removed {n} logo-like block(s)")
        removed += n

    if not removed:
        print("[=] No logo blocks found as strings")

    if "def print_banner(" not in src:
        fn = '''
def print_banner():
    line = "=" * 52
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
        idx = src.find("def main(")
        src = src[:idx] + fn + "\n" + src[idx:]
        print("[+] Injected print_banner")

    src = re.sub(
        r'(BANNER\s*=\s*r?"""[\s\S]*?_   _[\s\S]*?""")',
        'BANNER = ""',
        src,
        count=3,
    )
    src = re.sub(
        r"(BANNER\s*=\s*r?'''[\s\S]*?_   _[\s\S]*?''')",
        "BANNER = ''",
        src,
        count=3,
    )

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    print("""
Done. Test:

  python3 sentinel.py start

If old art remains:
  grep -n '_   _' sentinel.py | head
""")


if __name__ == "__main__":
    main()
