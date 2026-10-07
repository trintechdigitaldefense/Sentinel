#!/usr/bin/env python3
"""Wire Phase 5 CLI + hunt heartbeat + send_alert hygiene."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    cli_block = """
    elif command in (\"phase5\", \"p5\"):
        try:
            from modules.phase5 import phase5_self_check, heartbeat_write, ensure_hygiene_defaults, ensure_whatsapp_defaults
            ensure_hygiene_defaults()
            ensure_whatsapp_defaults()
            heartbeat_write({\"source\": \"phase5\"})
            print(phase5_self_check())
        except Exception as e:
            print(\"[!] phase5:\", e)
    elif command == \"autosubnet\":
        try:
            from modules.phase5 import auto_subnet_apply
            print(auto_subnet_apply())
        except Exception as e:
            print(\"[!] autosubnet:\", e)
    elif command == \"heartbeat\":
        try:
            from modules.phase5 import heartbeat_write, heartbeat_status
            print(heartbeat_write({\"source\": \"cli\"}))
            print(heartbeat_status())
        except Exception as e:
            print(\"[!] heartbeat:\", e)
    elif command == \"digest\":
        try:
            from modules.phase5 import alert_digest
            hours = 24
            if \"--hours\" in args:
                i = args.index(\"--hours\")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(alert_digest(hours))
        except Exception as e:
            print(\"[!] digest:\", e)
    elif command in (\"whatsapp-digest\", \"wa-digest\", \"digest-send\"):
        try:
            from modules.phase5 import whatsapp_digest
            hours = 24
            force = \"--force\" in args
            if \"--hours\" in args:
                i = args.index(\"--hours\")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(whatsapp_digest(hours=hours, force=force))
        except Exception as e:
            print(\"[!] whatsapp-digest:\", e)
    elif command == \"hygiene\":
        try:
            from modules.phase5 import hygiene_status, hygiene_reset, ensure_hygiene_defaults
            ensure_hygiene_defaults()
            if \"--reset\" in args:
                print(hygiene_reset())
            print(hygiene_status())
        except Exception as e:
            print(\"[!] hygiene:\", e)
    elif command in (\"status-json\", \"json-status\"):
        try:
            from modules.phase5 import status_json
            print(status_json())
        except Exception as e:
            print(\"[!] status-json:\", e)
    elif command == \"dashboard\":
        try:
            from modules.phase5 import dashboard_serve, dashboard_write
            if \"--write-only\" in args:
                print(dashboard_write())
            else:
                host, port = \"0.0.0.0\", 8787
                if \"--host\" in args:
                    host = args[args.index(\"--host\") + 1]
                if \"--port\" in args:
                    port = int(args[args.index(\"--port\") + 1])
                dashboard_serve(host, port)
        except Exception as e:
            print(\"[!] dashboard:\", e)
"""

    if "whatsapp-digest" not in src:
        for a in ['elif command == "uninstall":', 'elif command == "pdf"', 'elif command == "phase4"', "Unknown command"]:
            if a in src:
                src = src.replace(a, cli_block + "\n    " + a, 1)
                print("[+] CLI handlers inserted")
                break
        else:
            print("[!] CLI anchor missing")
    else:
        print("[=] CLI present")

    hunt_snip = "\n            try:\n                from modules.phase5 import heartbeat_from_hunt\n                heartbeat_from_hunt()\n            except Exception:\n                pass\n"
    if "heartbeat_from_hunt" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            end = wt + len("while True:")
            src = src[:end] + hunt_snip + src[end:]
            print("[+] Hunt heartbeat injected")
        elif "Cron integrity verified" in src:
            src = src.replace("Cron integrity verified", "Cron integrity verified" + hunt_snip, 1)
            print("[+] Hunt heartbeat near cron log")
        else:
            print("[!] Hunt inject point missing")
    else:
        print("[=] Hunt heartbeat present")

    hy_snip = "\n    try:\n        from modules.phase5 import hygiene_should_emit\n        _hy = hygiene_should_emit(str(alert_type), None)\n        if not _hy.get(\"allow\", True):\n            return\n    except Exception:\n        pass\n"
    if "hygiene_should_emit" not in src:
        m = re.search(r"def send_alert\s*\([^)]*\):\n", src)
        if m:
            src = src[: m.end()] + hy_snip + src[m.end() :]
            print("[+] Hygiene gate in send_alert")
        else:
            print("[!] send_alert not found")
    else:
        print("[=] Hygiene present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] Syntax OK — Phase 5 wired")

if __name__ == "__main__":
    main()
