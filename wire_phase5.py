#!/usr/bin/env python3
"""Wire Phase 5 CLI commands into sentinel.py"""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

HANDLERS = r'''
    # --- Phase 5 commands ---
    elif command in ("phase5", "p5"):
        try:
            from modules.phase5 import phase5_self_check, heartbeat_write
            heartbeat_write()
            print(phase5_self_check())
        except Exception as e:
            print(f"[!] phase5: {e}")
    elif command == "autosubnet":
        try:
            from modules.phase5 import auto_subnet_apply
            print(auto_subnet_apply())
        except Exception as e:
            print(f"[!] autosubnet: {e}")
    elif command == "heartbeat":
        try:
            from modules.phase5 import heartbeat_write, heartbeat_status
            print(heartbeat_write())
            print(heartbeat_status())
        except Exception as e:
            print(f"[!] heartbeat: {e}")
    elif command == "digest":
        try:
            from modules.phase5 import alert_digest
            hours = 24
            if "--hours" in args:
                i = args.index("--hours")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(alert_digest(hours))
        except Exception as e:
            print(f"[!] digest: {e}")
    elif command in ("status-json", "json-status"):
        try:
            from modules.phase5 import status_json
            print(status_json())
        except Exception as e:
            print(f"[!] status-json: {e}")
    elif command == "dashboard":
        try:
            from modules.phase5 import dashboard_serve, dashboard_write
            if "--write-only" in args:
                print(dashboard_write())
            else:
                host, port = "0.0.0.0", 8787
                if "--host" in args:
                    host = args[args.index("--host") + 1]
                if "--port" in args:
                    port = int(args[args.index("--port") + 1])
                dashboard_serve(host, port)
        except Exception as e:
            print(f"[!] dashboard: {e}")
'''


def main():
    if not ENGINE.exists():
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "modules.phase5" not in src and "phase5_self_check" not in src:
        anchors = [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command == "phase4"',
            'logger.error(f"{C.RED}\u2717 Unknown command',
            'Unknown command',
        ]
        inserted = False
        for a in anchors:
            if a in src:
                src = src.replace(a, HANDLERS + "\n    " + a, 1)
                inserted = True
                print(f"[+] Phase 5 handlers inserted before: {a[:40]}")
                break
        if not inserted:
            print("[!] Could not find CLI anchor")
            sys.exit(1)
    else:
        print("[=] Phase 5 handlers already present")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print("[+] Syntax OK")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax: {e}")
        sys.exit(1)

    print("""
[+] Phase 5 wired

  python3 sentinel.py phase5
  python3 sentinel.py autosubnet
  python3 sentinel.py heartbeat
  python3 sentinel.py digest
  python3 sentinel.py status-json
  python3 sentinel.py dashboard
""")


if __name__ == "__main__":
    main()
