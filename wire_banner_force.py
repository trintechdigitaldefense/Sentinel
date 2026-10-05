#!/usr/bin/env python3
"""Force SENTINEL banner on every path (menu + start + hunt)."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

OLD_LOGO = """  _   _      _   _        _     _______ _
 | \\ | |    | \\ | |      | |   |__   __(_)
 |  \\| | ___|  \\| | __ _ | |  __ _| |__  _ _ __ ___
 | . ` |/ _ \\ . ` |/ _` || | / _` | '_ \\| | '_ ` _ \\
 | |\\  |  __/ |\\  | (_| || || (_| | |_) | | | | | | |
 |_| \\_|\\___|_| \\_|\\__,_||_| \\__,_|_.__/|_|_| |_| |_|"""

NEW_LOGO = """  ____  _____ _   _ _____ ___ _   _ _____ _
 / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |
 \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |
  ___) | |___| |\\  | | |  | || |\\  | |___| |___
 |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|"""

PRINT_BANNER = '''
def print_banner():
    """SENTINEL banner — all commands."""
    art = r"""
  ____  _____ _   _ _____ ___ _   _ _____ _
 / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |
 \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |
  ___) | |___| |\\  | | |  | || |\\  | |___| |___
 |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|
"""
    print(f"{C.CYAN}{C.BOLD}{art}{C.RESET}")
    try:
        ver = __version__
    except Exception:
        ver = "2.5.0"
    print(f"{C.BOLD}  SENTINEL v{ver}{C.RESET}")
    print(f"{C.GRAY}  TrinTech Digital Defense — Active Deception · Persistence Hunting · Line of Defense{C.RESET}")
    print(f"{C.GRAY}  {'─' * 66}{C.RESET}\\n")
'''


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py missing")
        sys.exit(1)
    src = ENGINE.read_text()

    if OLD_LOGO in src:
        src = src.replace(OLD_LOGO, NEW_LOGO)
        print("[+] Replaced old logo string(s)")
    else:
        loose = re.compile(
            r"  _   _\s+_   _\s+_+\s+_+\s+_+\s*_\n"
            r" \| \\\\ \| \|.*\n"
            r"(?:.*\n){3}"
            r" \|_| \\\\_\|\\\\___\|.*",
            re.MULTILINE,
        )
        src2, c = loose.subn(NEW_LOGO, src)
        if c:
            src = src2
            print(f"[+] Replaced {c} logo block(s) via regex")
        else:
            print("[=] Old logo exact block not found")

    pattern = re.compile(
        r"def print_banner\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        re.DOTALL,
    )
    m = pattern.search(src)
    if m:
        src = src[: m.start()] + PRINT_BANNER.strip() + "\n\n\n" + src[m.end() :]
        print("[+] print_banner() rewritten")
    else:
        print("[!] print_banner not found")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    p = Path.home() / ".sentinel/data/self_integrity.json"
    if p.exists():
        p.unlink()
        print("[+] Cleared self-integrity baseline")

    print("""
Done. Test:

  python3 sentinel.py start

Banner should be SENTINEL block letters only.
""")


if __name__ == "__main__":
    main()
