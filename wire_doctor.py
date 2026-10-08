#!/usr/bin/env python3
"""Wire 'doctor' CLI into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = """
    elif command in ("doctor", "health", "check"):
        try:
            from modules.doctor import run_doctor
            run_doctor(verbose=True)
        except Exception as e:
            print("[!] doctor:", e)
"""

HELP_LINE = "  sentinel doctor                 Readiness check (OK/WARN/FAIL)\n"

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing or not assembled — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()
    if 'command in ("doctor"' in src or 'command == "doctor"' in src:
        print("[=] doctor already wired")
    else:
        inserted = False
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("phase7"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                inserted = True
                print("[+] doctor CLI inserted")
                break
        if not inserted:
            print("[!] could not find CLI anchor")
            sys.exit(1)
    if "sentinel doctor" not in src and "USAGE:" in src:
        src = src.replace("USAGE:\n", "USAGE:\n" + HELP_LINE, 1)
        print("[+] help line added")
    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] doctor wired OK")

if __name__ == "__main__":
    main()
