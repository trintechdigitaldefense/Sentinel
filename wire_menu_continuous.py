#!/usr/bin/env python3
"""
Update interactive menu:
  1 = Full start once, then continuous hunt (real protection loop)
  3 = Hunt only (continuous)
"""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

NEW_MENU = r'''
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
        """One full start, then continuous hunt until Ctrl+C."""
        print(f"\n  {C.CYAN}{C.BOLD}[*] Full start (scan + decoys + checks)…{C.RESET}\n")
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
        ("8",  "Phase 4 tools (baseline, Caribbean, playbooks…)", ("__phase4__",)),
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
        print("  " + "─" * 54)
        for num, label, _ in items:
            print(f"  {C.BOLD}{num:>2}{C.RESET}  {label}")
        print("  " + "─" * 54)

    def loop(items, title):
        while True:
            try:
                print_banner()
            except Exception:
                print("\n  SENTINEL — Interactive Menu\n")
            show(items, title)
            pick = input(f"\n  {C.BOLD}Select:{C.RESET} ").strip()
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
                input(f"\n  {C.GRAY}Press Enter to continue…{C.RESET}")
            except EOFError:
                pass

    loop(main_items, "MAIN MENU")

'''


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py not found")
        sys.exit(1)
    src = ENGINE.read_text()

    if "def interactive_menu(" not in src:
        print("[!] Run python3 wire_menu.py first")
        sys.exit(1)

    pattern = re.compile(
        r"def interactive_menu\([^)]*\):.*?(?=\n(?:def |class |\nif __name__))",
        re.DOTALL,
    )
    m = pattern.search(src)
    if not m:
        print("[!] Could not find interactive_menu to replace")
        sys.exit(1)

    src = src[: m.start()] + NEW_MENU.strip() + "\n\n\n" + src[m.end() :]
    ENGINE.write_text(src)

    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    print("""
[+] Menu updated — continuous protection

  python3 sentinel.py

  1  = scan + decoys + checks ONCE, then continuous HUNT
  3  = hunt only (already continuous)

Leave option 1 running for real protection. Ctrl+C returns to menu.
""")


if __name__ == "__main__":
    main()
