#!/usr/bin/env python3
"""Wire Phase 6 CLI: service, digest-cron, phase6. Strengthen hunt HB + hygiene."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = """
    elif command in ("phase6", "p6"):
        try:
            from modules.phase6 import phase6_self_check
            print(phase6_self_check())
        except Exception as e:
            print("[!] phase6:", e)
    elif command in ("service-install", "install-service", "always-on"):
        try:
            from modules.phase6 import install_service, service_status
            system = "--user" not in args
            print(install_service(system=system))
            print(service_status())
        except Exception as e:
            print("[!] service-install:", e)
    elif command in ("service-status", "service"):
        try:
            from modules.phase6 import service_status
            print(service_status())
        except Exception as e:
            print("[!] service-status:", e)
    elif command in ("service-stop", "stop-service"):
        try:
            from modules.phase6 import service_stop
            print(service_stop())
        except Exception as e:
            print("[!] service-stop:", e)
    elif command in ("digest-cron", "schedule-digest"):
        try:
            from modules.phase6 import install_digest_cron, remove_digest_cron
            if "--remove" in args:
                print(remove_digest_cron())
            else:
                sch = "weekly" if "--weekly" in args else "daily"
                print(install_digest_cron(sch))
        except Exception as e:
            print("[!] digest-cron:", e)
"""

HUNT_HB = """
            try:
                from modules.phase5 import heartbeat_from_hunt
                heartbeat_from_hunt()
            except Exception:
                pass
"""

HYGIENE = """
    try:
        from modules.phase5 import hygiene_should_emit
        _hy = hygiene_should_emit(str(alert_type), None)
        if not _hy.get("allow", True):
            return
    except Exception:
        pass
"""

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "service-install" not in src:
        for a in ['elif command == "uninstall":', 'elif command == "pdf"', "Unknown command"]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] Phase 6 CLI inserted")
                break
    else:
        print("[=] Phase 6 CLI present")

    if "heartbeat_from_hunt" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            end = wt + len("while True:")
            src = src[:end] + HUNT_HB + src[end:]
            print("[+] Hunt heartbeat injected")
        else:
            print("[!] no while True for hunt HB")
    else:
        print("[=] Hunt heartbeat present")

    if "hygiene_should_emit" not in src:
        m = re.search(r"def send_alert\s*\([^)]*\):\n", src)
        if m:
            src = src[:m.end()] + HYGIENE + src[m.end():]
            print("[+] Hygiene gate in send_alert")
        else:
            print("[!] send_alert not found")
    else:
        print("[=] Hygiene present")

    needle = '("12", "Status", ("status",)),'
    if needle in src and "Always-on" not in src:
        inject = needle + '\n        ("13", "Always-on service (systemd)", ("service-install",)),\n        ("14", "Service status", ("service-status",)),\n        ("15", "Schedule WhatsApp digest (daily cron)", ("digest-cron",)),'
        src = src.replace(needle, inject, 1)
        print("[+] Menu items 13-15 added")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] Syntax OK — Phase 6 wired")

if __name__ == "__main__":
    main()
