#!/usr/bin/env python3
"""Wire F01 PDF drift, F02 ATT&CK, F03 bot, F05-08 detection into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = r'''
    elif command in ("drift-pdf", "report-drift"):
        try:
            from modules.drift_pdf import generate_drift_pdf
            print(generate_drift_pdf())
        except Exception as e:
            print("[!] drift-pdf:", e)
    elif command in ("attack", "att&ck", "mitre"):
        try:
            from modules.attack_map import summarize_techniques, print_map_sample
            print_map_sample()
            from pathlib import Path as P
            alerts = []
            ap = P.home() / ".sentinel/data/alerts.log"
            if ap.exists():
                for line in ap.read_text(errors="ignore").splitlines()[-50:]:
                    alerts.append({"reason": line[:80], "type": "alert"})
            print({"techniques_observed": summarize_techniques(alerts)})
        except Exception as e:
            print("[!] attack:", e)
    elif command in ("bot", "telegram-bot"):
        try:
            from modules.bot import run_bot_loop, ensure_bot_defaults, bot_config
            ensure_bot_defaults()
            cfg = bot_config()
            print("telegram config:", {k: cfg[k] for k in ("enabled", "chat_id")})
            run_bot_loop()
        except Exception as e:
            print("[!] bot:", e)
    elif command in ("bot-test",):
        try:
            from modules.bot import handle_command, ensure_bot_defaults
            ensure_bot_defaults()
            print(handle_command("STATUS"))
        except Exception as e:
            print("[!] bot-test:", e)
    elif command in ("usb", "usb-watch"):
        try:
            from modules.usb_watch import check
            print(check())
        except Exception as e:
            print("[!] usb:", e)
    elif command in ("lateral",):
        try:
            from modules.lateral import check
            print(check())
        except Exception as e:
            print("[!] lateral:", e)
    elif command in ("dns", "dns-watch"):
        try:
            from modules.dns_watch import check
            print(check())
        except Exception as e:
            print("[!] dns:", e)
    elif command in ("persistence-baseline",):
        try:
            from modules.persistence_hunt import create_baseline
            print(create_baseline())
        except Exception as e:
            print("[!] persistence-baseline:", e)
    elif command in ("persistence", "persistence-check"):
        try:
            from modules.persistence_hunt import check
            print(check())
        except Exception as e:
            print("[!] persistence:", e)
    elif command in ("detect", "tier2"):
        try:
            from modules.usb_watch import check as usb_check
            from modules.lateral import check as lat_check
            from modules.dns_watch import check as dns_check
            from modules.persistence_hunt import check as per_check
            from modules.attack_map import tag_alert
            bundle = {
                "usb": usb_check(),
                "lateral": lat_check(),
                "dns": dns_check(),
                "persistence": per_check(),
            }
            for key in bundle:
                evs = bundle[key].get("events") or []
                bundle[key]["events"] = [tag_alert(e) for e in evs[:10]]
            print(bundle)
        except Exception as e:
            print("[!] detect:", e)
'''

HUNT_TIER2 = r'''
            try:
                from modules.deadman import emit_heartbeat
                emit_heartbeat("hunt")
            except Exception:
                pass
            try:
                from modules.usb_watch import check as _usb_c
                from modules.lateral import check as _lat_c
                from modules.dns_watch import check as _dns_c
                from modules.persistence_hunt import check as _per_c
                from modules.attack_map import tag_alert
                for _label, _fn in (("usb", _usb_c), ("lateral", _lat_c), ("dns", _dns_c), ("persistence", _per_c)):
                    try:
                        _res = _fn()
                        for _ev in (_res.get("events") or [])[:5]:
                            _ev = tag_alert(_ev)
                            _msg = f"TIER2/{_label}: {_ev.get('reason')} {_ev.get('detail') or _ev.get('path') or _ev}"
                            try:
                                logger.warning(_msg[:300])
                            except Exception:
                                print("[!]", _msg[:300])
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                from modules.bot import poll_once, bot_config
                if bot_config().get("enabled"):
                    poll_once()
            except Exception:
                pass
'''

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "drift-pdf" not in src:
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("doctor"',
            'elif command in ("drift"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] revenue + tier2 CLI")
                break
        else:
            print("[!] CLI anchor missing")
    else:
        print("[=] revenue CLI present")

    if "modules.usb_watch" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            end = wt + len("while True:")
            src = src[:end] + HUNT_TIER2 + src[end:]
            print("[+] hunt tier2 + bot poll hooks")
        else:
            print("[!] no hunt loop for tier2")
    else:
        print("[=] tier2 hunt hooks present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] wire_revenue_tier2 OK")

if __name__ == "__main__":
    main()
