#!/usr/bin/env python3
"""Wire F13-17 bonus features into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = r'''
    elif command in ("rules", "rules-check"):
        try:
            from modules.rules_engine import load_rules, check_events, ensure_default_rules
            ensure_default_rules()
            print({"rules": len(load_rules()), "sample": check_events([{"command": "bash -i", "reason": "reverse_shell"}])})
        except Exception as e:
            print("[!] rules:", e)
    elif command in ("devices", "radar", "new-devices"):
        try:
            from modules.device_radar import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] radar:", e)
    elif command in ("device-approve",):
        try:
            import sys as _sys
            from modules.device_radar import approve
            key = _sys.argv[2] if len(_sys.argv) > 2 else ""
            print(approve(key))
        except Exception as e:
            print("[!] device-approve:", e)
    elif command in ("tripwire-deploy",):
        try:
            from modules.ransomware_tripwire import deploy
            print(deploy())
        except Exception as e:
            print("[!] tripwire-deploy:", e)
    elif command in ("tripwire", "ransomware"):
        try:
            from modules.ransomware_tripwire import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] tripwire:", e)
    elif command in ("external", "posture"):
        try:
            import sys as _sys
            from modules.external_posture import check
            domain = _sys.argv[2] if len(_sys.argv) > 2 else None
            print(check(domain=domain))
        except Exception as e:
            print("[!] external:", e)
    elif command in ("fleet", "fleet-console"):
        try:
            from modules.fleet_console import print_console, write_html
            print_console()
            print("HTML:", write_html())
        except Exception as e:
            print("[!] fleet:", e)
    elif command in ("bonus-test", "test-all"):
        try:
            print("=== BONUS SELF-TEST ===")
            from modules.rules_engine import ensure_default_rules, load_rules, check_events
            ensure_default_rules()
            print("rules", len(load_rules()), check_events([{"command": "bash -i"}])["match_count"])
            from modules.device_radar import check as radar
            print("radar", radar()["scanned"], "new", radar()["new_count"])
            from modules.ransomware_tripwire import deploy, check as tw
            print("tripwire deploy", deploy()["files"])
            print("tripwire check", tw()["count"])
            from modules.external_posture import check as ext
            print("external", ext()["ok"])
            from modules.fleet_console import collect_local
            print("fleet clients", len(collect_local()["clients"]))
            print("=== BONUS SELF-TEST OK ===")
        except Exception as e:
            print("[!] bonus-test:", e)
'''

HUNT = r'''
            try:
                from modules.device_radar import check as _rad
                from modules.ransomware_tripwire import check as _tw
                from modules.rules_engine import evaluate
                from modules.attack_map import tag_alert
                from modules.suppressions import filter_events
                for _lab, _fn in (("radar", _rad), ("tripwire", _tw)):
                    try:
                        _r = _fn()
                        for _ev in filter_events(_r.get("events") or [])[:3]:
                            _ev = tag_alert(_ev)
                            _hits = evaluate(_ev)
                            _msg = f"BONUS/{_lab}: {_ev.get('detail') or _ev}"
                            if _hits:
                                _msg += f" rules={[h.get('id') for h in _hits]}"
                            try:
                                logger.warning(_msg[:300])
                            except Exception:
                                print("[!]", _msg[:300])
                    except Exception:
                        pass
            except Exception:
                pass
'''

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()
    if "bonus-test" not in src:
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("doctor"',
            'elif command in ("portal"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] bonus CLI")
                break
        else:
            print("[!] CLI anchor missing")
    else:
        print("[=] bonus CLI present")

    if "modules.device_radar" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            src = src[: wt + len("while True:")] + HUNT + src[wt + len("while True:"):]
            print("[+] hunt bonus hooks")
        else:
            print("[!] no hunt loop")
    else:
        print("[=] bonus hunt present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] wire_bonus OK")

if __name__ == "__main__":
    main()
