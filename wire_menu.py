#!/usr/bin/env python3
"""
Wire interactive numbered menu into Sentinel.

  python3 wire_menu.py
  python3 sentinel.py          # shows menu
  python3 sentinel.py start    # still works
"""
from pathlib import Path
import py_compile
import sys

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"

MENU_CODE = r'''
def interactive_menu(config=None, logger=None):
    """Numbered menu for easy field / client use."""
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    eng = _Path(__file__).resolve()

    def run(*args):
        try:
            subprocess.call([_sys.executable, str(eng), *args])
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}Stopped.{C.RESET}")

    main_items = [
        ("1",  "Start full defense (scan + decoys + Line of Defense)", ("start",)),
        ("2",  "Quick network scan", ("scan",)),
        ("3",  "Persistence hunt (continuous) — Ctrl+C to stop", ("hunt",)),
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
            run(*args)
            try:
                input(f"\n  {C.GRAY}Press Enter to continue…{C.RESET}")
            except EOFError:
                pass

    loop(main_items, "MAIN MENU")

'''


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py not found — cd to repo root first")
        sys.exit(1)

    src = ENGINE.read_text()

    if "def interactive_menu(" not in src:
        idx = src.find("\ndef main(")
        if idx < 0:
            idx = src.find("def main(")
        if idx < 0:
            print("[!] Could not find def main(")
            sys.exit(1)
        src = src[:idx] + "\n" + MENU_CODE + "\n" + src[idx:]
        print("[+] interactive_menu() added")
    else:
        print("[=] interactive_menu() already present")

    if "wire_menu_v2" not in src:
        old = "def main():\n"
        new = '''def main():
    # wire_menu_v2 — numbered menu when no CLI command is given
    if len(sys.argv) < 2:
        interactive_menu()
        return
'''
        if old in src:
            src = src.replace(old, new, 1)
            print("[+] Menu hooked (no-arg → interactive menu)")
        else:
            print("[!] Could not hook main() — add manually")
            ENGINE.write_text(src)
            sys.exit(1)
    else:
        print("[=] Menu already hooked")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax error: {e}")
        print("    Fix: git checkout -- sentinel.py && python3 setup.py && python3 wire_menu.py")
        sys.exit(1)

    print("""
==================================================
  MENU READY
==================================================

  python3 sentinel.py

MAIN MENU
  1   Start full defense
  2   Quick network scan
  3   Persistence hunt
  4   Deploy deception / canaries
  5   Integrity baseline
  6   Process scan
  7   Report
  8   Phase 4 tools  → submenu
  9   System info
 10   Alerts
 11   Hardening audit
 12   Status
  0   Exit

Old commands still work:
  python3 sentinel.py start
  python3 sentinel.py hunt
""")


if __name__ == "__main__":
    main()
