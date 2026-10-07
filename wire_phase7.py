#!/usr/bin/env python3
"""Wire Phase 7: central, agents, quiet hours, release, Windows agent path."""
from pathlib import Path
import py_compile
import re
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = """
    elif command in ("phase7", "p7"):
        try:
            from modules.phase7 import phase7_self_check
            print(phase7_self_check())
        except Exception as e:
            print("[!] phase7:", e)
    elif command in ("central", "central-status"):
        try:
            from modules.phase7 import central_serve
            host, port = "0.0.0.0", 8790
            if "--host" in args:
                host = args[args.index("--host") + 1]
            if "--port" in args:
                port = int(args[args.index("--port") + 1])
            central_serve(host, port)
        except Exception as e:
            print("[!] central:", e)
    elif command in ("agents", "agents-list"):
        try:
            from modules.phase7 import agents_list
            print(agents_list())
        except Exception as e:
            print("[!] agents:", e)
    elif command in ("agent-report", "report-in"):
        try:
            from modules.phase7 import agent_self_report
            url = None
            if "--central" in args:
                url = args[args.index("--central") + 1]
            print(agent_self_report(url))
        except Exception as e:
            print("[!] agent-report:", e)
    elif command in ("quiet", "quiet-hours"):
        try:
            from modules.phase7 import quiet_status, quiet_set
            if "--on" in args:
                print(quiet_set(enabled=True))
            elif "--off" in args:
                print(quiet_set(enabled=False))
            else:
                start = end = None
                if "--start" in args:
                    start = args[args.index("--start") + 1]
                if "--end" in args:
                    end = args[args.index("--end") + 1]
                if start or end:
                    print(quiet_set(start=start, end=end))
                else:
                    print(quiet_status())
        except Exception as e:
            print("[!] quiet:", e)
    elif command in ("release", "version"):
        try:
            from modules.phase7 import release_info
            print(release_info())
        except Exception as e:
            print("[!] release:", e)
    elif command in ("win-agent", "windows-agent"):
        try:
            from modules.phase7 import write_windows_agent
            print(write_windows_agent())
        except Exception as e:
            print("[!] win-agent:", e)
"""

QUIET_GATE = """
    try:
        from modules.phase7 import quiet_should_suppress
        _qs = quiet_should_suppress(str(alert_type))
        if _qs.get("suppress"):
            return
    except Exception:
        pass
"""

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "phase7_self_check" not in src and "quiet-hours" not in src:
        for a in ['elif command == "uninstall":', 'elif command == "pdf"', "Unknown command"]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] Phase 7 CLI")
                break
    else:
        print("[=] Phase 7 CLI present")

    if "quiet_should_suppress" not in src:
        m = re.search(r"def send_alert\s*\([^)]*\):\n", src)
        if m:
            src = src[:m.end()] + QUIET_GATE + src[m.end():]
            print("[+] Quiet hours gate in send_alert")
        else:
            print("[!] send_alert not found")
    else:
        print("[=] Quiet gate present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] Phase 7 wired")

if __name__ == "__main__":
    main()
