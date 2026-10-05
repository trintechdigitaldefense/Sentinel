#!/usr/bin/env python3
"""Replace banner with clean SENTINEL ASCII art."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

NEW_BANNER = r'''
def print_banner():
    """Clean SENTINEL banner — TrinTech Digital Defense."""
    art = r"""
  ____  _____ _   _ _____ ___ _   _ _____ _
 / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |
 \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |
  ___) | |___| |\\  | | |  | || |\\  | |___| |___
 |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|

"""
    print(f"{C.CYAN}{C.BOLD}{art}{C.RESET}")
    print(f"{C.BOLD}  SENTINEL v{__version__}{C.RESET}")
    print(f"{C.GRAY}  TrinTech Digital Defense — Active Deception · Persistence Hunting · Line of Defense{C.RESET}")
    print(f"{C.GRAY}  {'─' * 66}{C.RESET}\n")
'''

def main():
    if not ENGINE.exists():
        print("[!] sentinel.py not found")
        sys.exit(1)
    src = ENGINE.read_text()

    if "def print_banner" in src:
        pattern = re.compile(
            r"def print_banner\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
            re.DOTALL,
        )
        m = pattern.search(src)
        if m:
            src = src[: m.start()] + NEW_BANNER.strip() + "\n\n\n" + src[m.end() :]
            print("[+] print_banner() replaced with SENTINEL art")
        else:
            src = src.replace("def print_banner", "def print_banner_OLD", 1)
            idx = src.find("\ndef main(")
            if idx < 0:
                idx = src.find("def main(")
            src = src[:idx] + "\n" + NEW_BANNER + "\n" + src[idx:]
            print("[+] print_banner() added (old renamed)")
    else:
        idx = src.find("\ndef main(")
        if idx < 0:
            idx = src.find("def main(")
        src = src[:idx] + "\n" + NEW_BANNER + "\n" + src[idx:]
        print("[+] print_banner() added")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    print("""
[+] Banner updated

  python3 sentinel.py

You should see SENTINEL block letters.
""")

if __name__ == "__main__":
    main()
