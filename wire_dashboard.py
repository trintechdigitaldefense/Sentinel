#!/usr/bin/env python3
"""Wire dashboard CLI into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = r'''
    elif command in ("dashboard", "dash", "ui"):
        try:
            from modules.dashboard import start_dashboard
            start_dashboard()
        except Exception as e:
            print("[!] dashboard:", e)
    elif command in ("dashboard-url", "dash-url"):
        try:
            from modules.dashboard import ensure_token
            tok, port, dash = ensure_token()
            print("http://127.0.0.1:%d/?token=%s" % (port, tok))
            print("control:", dash.get("allow_control", True))
        except Exception as e:
            print("[!] dashboard-url:", e)
'''


def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing")
        sys.exit(1)
    src = ENGINE.read_text()
    if "dashboard-url" not in src:
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("doctor"',
            'elif command in ("bonus-test"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] dashboard CLI")
                break
        else:
            print("[!] CLI anchor missing")
    else:
        print("[=] dashboard CLI present")
    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] wire_dashboard OK")


if __name__ == "__main__":
    main()
