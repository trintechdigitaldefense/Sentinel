#!/usr/bin/env python3
"""Wire Feature 01 (drift) + Feature 11 (dead-man) into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = r'''
    elif command in ("drift", "drift-report"):
        try:
            from modules.drift import print_report
            print_report()
        except Exception as e:
            print("[!] drift:", e)
    elif command in ("deadman", "dead-man", "heartbeat-check"):
        try:
            from modules.deadman import print_status, ensure_defaults
            ensure_defaults()
            print_status()
        except Exception as e:
            print("[!] deadman:", e)
'''

HUNT_HB = r'''
            try:
                from modules.deadman import emit_heartbeat
                emit_heartbeat("hunt")
            except Exception:
                try:
                    from modules.phase5 import heartbeat_from_hunt
                    heartbeat_from_hunt()
                except Exception:
                    pass
            try:
                from modules.deadman import check_fleet
                _dm = check_fleet()
                if _dm.get("alert"):
                    try:
                        logger.warning(_dm["alert"])
                    except Exception:
                        print("[!]", _dm["alert"])
            except Exception:
                pass
'''

INTEGRITY_EXTRA = r'''
        try:
            from modules.drift import compute_score
            compute_score([])
        except Exception:
            pass
'''


def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "drift-report" not in src and '"drift"' not in src:
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("doctor"',
            'elif command in ("phase7"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] drift + deadman CLI")
                break
        else:
            print("[!] CLI anchor not found")
    else:
        print("[=] drift CLI present")

    if "modules.deadman import emit_heartbeat" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            end = wt + len("while True:")
            src = src[:end] + HUNT_HB + src[end:]
            print("[+] hunt deadman heartbeat + fleet check")
        else:
            print("[!] no hunt while True — deadman still available via CLI")
    else:
        print("[=] deadman hunt hook present")

    if "modules.drift import compute_score" not in src:
        for a in ['elif command == "integrity"', 'elif command in ("integrity"']:
            if a in src:
                src = src.replace(a, a + "\n" + INTEGRITY_EXTRA, 1)
                print("[+] integrity drift snapshot hook")
                break
        else:
            print("[=] integrity CLI not found — use: sentinel drift after integrity")
    else:
        print("[=] drift integrity hook present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] wire_drift_deadman OK")


if __name__ == "__main__":
    main()
