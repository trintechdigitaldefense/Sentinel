#!/usr/bin/env python3
"""
One-shot UI fix for Sentinel:
  1. Delete every old-logo art line from sentinel.py
  2. Install simple SENTINEL print_banner()
  3. Ensure interactive menu opens on: python3 sentinel.py
"""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

MENU_CODE = r'''
def interactive_menu(config=None, logger=None):
    """Numbered menu — option 1 = start + continuous hunt."""
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    eng = _Path(__file__).resolve()

    def run(*args):
        try:
            subprocess.call([_sys.executable, str(eng), *args])
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}Stopped.{C.RESET}")

    def run_continuous_defense():
        print(f"\n  {C.CYAN}{C.BOLD}[*] Full start (scan + decoys + checks)...{C.RESET}\n")
        run("start")
        print(f"\n  {C.GREEN}{C.BOLD}[*] Continuous protection ON — hunt loop{C.RESET}")
        print(f"  {C.GRAY}Ctrl+C to stop and return to menu{C.RESET}\n")
        run("hunt")

    main_items = [
        ("1",  "START continuous protection (scan once + stay hunting)", ("__continuous__",)),
        ("2",  "Quick network scan (one-shot)", ("scan",)),
        ("3",  "Hunt only (continuous) — Ctrl+C to stop", ("hunt",)),
        ("4",  "Deploy deception / canary traps", ("deception",)),
        ("5",  "Integrity baseline (FIM)", ("integrity",)),
        ("6",  "Scan suspicious processes", ("processes",)),
        ("7",  "Show full report", ("report",)),
        ("8",  "Phase 4 tools (baseline, Caribbean, playbooks...)", ("__phase4__",)),
        ("9",  "System info", ("info",)),
        ("10", "View alerts", ("alerts",)),
        ("11", "Hardening audit", ("hardening",)),
        ("12", "Status", ("status",)),
        ("0",  "Exit", ("__exit__",)),
    ]

    p4_items = [
        ("1", "Phase 4 self-check", ("phase4",)),
        ("2", "Build behavioral baseline", ("baseline",)),
        ("3", "Check vs baseline (anomalies)", ("baseline", "check")),
        ("4", "Caribbean / T&T threat pack", ("caribbean",)),
        ("5", "List response playbooks", ("playbook",)),
        ("6", "Export evidence pack (24h)", ("evidence", "--hours", "24")),
        ("7", "Offline alert queue", ("offline",)),
        ("0", "Back to main menu", ("__back__",)),
    ]

    def show(items, title):
        print(f"\n{C.CYAN}{C.BOLD}  {title}{C.RESET}")
        print("  " + "-" * 54)
        for num, label, _ in items:
            print(f"  {C.BOLD}{num:>2}{C.RESET}  {label}")
        print("  " + "-" * 54)

    def loop(items, title):
        while True:
            try:
                print_banner()
            except Exception:
                print("\n  SENTINEL — Interactive Menu\n")
            show(items, title)
            try:
                pick = input(f"\n  {C.BOLD}Select:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return "exit"
            mapping = {n: args for n, _, args in items}
            if pick not in mapping:
                print(f"  {C.RED}Invalid choice — try again{C.RESET}")
                continue
            args = mapping[pick]
            if args[0] == "__exit__":
                print(f"\n  {C.GREEN}Goodbye.{C.RESET}\n")
                return "exit"
            if args[0] == "__back__":
                return "back"
            if args[0] == "__phase4__":
                loop(p4_items, "PHASE 4 — Advanced tools")
                continue
            if args[0] == "__continuous__":
                run_continuous_defense()
            else:
                run(*args)
            try:
                input(f"\n  {C.GRAY}Press Enter to continue...{C.RESET}")
            except EOFError:
                pass

    loop(main_items, "MAIN MENU")

'''

BANNER_FN = '''
def print_banner():
    """Simple SENTINEL banner."""
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


def is_art_line(s: str) -> bool:
    t = s.rstrip("\n\r")
    if not t.strip():
        return False
    if "print_banner" in t or "def " in t or "import " in t:
        return False
    if "C." in t and ("print" in t or "BOLD" in t):
        return False
    if re.match(r"^  _   _\s+_   _", t):
        return True
    if re.match(r"^ \|[ .\\\\|_]", t) and "____" not in t and "print" not in t:
        if re.search(r"[|/\\\\_]", t) and len(t) > 20 and "=" not in t.split("#")[0]:
            if "(" in t or ")" in t or "{" in t:
                return False
            return True
    if re.match(r"^ \|_| \\\\\|_\|", t):
        return True
    return False


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py missing")
        sys.exit(1)

    src = ENGINE.read_text()
    lines = src.splitlines(True)
    kept = []
    dropped = 0
    for line in lines:
        if is_art_line(line):
            dropped += 1
            continue
        kept.append(line)
    src = "".join(kept)
    print(f"[+] Dropped {dropped} old logo art lines")

    src = re.sub(
        r"\ndef print_banner\s*\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        "\n",
        src,
        flags=re.DOTALL,
    )
    src = re.sub(
        r"\ndef interactive_menu\s*\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        "\n",
        src,
        flags=re.DOTALL,
    )

    src = src.replace(
        "    if len(sys.argv) < 2:\n        interactive_menu()\n        return\n",
        "",
    )

    idx = src.find("\ndef main(")
    if idx < 0:
        idx = src.find("def main(")
    if idx < 0:
        print("[!] main() not found")
        sys.exit(1)
    src = src[:idx] + "\n" + BANNER_FN + "\n" + MENU_CODE + "\n" + src[idx:]

    if "def main():\n" in src:
        src = src.replace(
            "def main():\n",
            "def main():\n"
            "    # fix_ui: open numbered menu when no command given\n"
            "    if len(sys.argv) < 2:\n"
            "        interactive_menu()\n"
            "        return\n",
            1,
        )
        print("[+] Menu hooked on python3 sentinel.py")

    src = re.sub(r"print\(\s*BANNER\s*\)", "print_banner()", src)
    src = re.sub(r"print\(\s*banner\s*\)", "print_banner()", src)

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
        print("[+] Integrity baseline cleared")

    hits = [i + 1 for i, L in enumerate(ENGINE.read_text().splitlines()) if "_   _" in L and "print" not in L]
    if hits:
        print(f"[!] Still has '_   _' on lines: {hits[:10]}")
    else:
        print("[+] No leftover '_   _' logo markers")

    print("""
DONE. Test both:

  python3 sentinel.py
      → should show MAIN MENU (numbers 0-12)

  python3 sentinel.py start
      → should show simple ===== SENTINEL ===== banner only
""")


if __name__ == "__main__":
    main()
