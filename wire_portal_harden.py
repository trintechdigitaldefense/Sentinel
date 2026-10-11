#!/usr/bin/env python3
"""Wire F04 portal + F09-12 hardening into sentinel.py."""
from pathlib import Path
import py_compile
import sys

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI = r'''
    elif command in ("portal", "webview"):
        try:
            from modules.webview import start_portal, ensure_portal_token
            tok = ensure_portal_token()
            print("Portal token:", tok)
            start_portal()
        except Exception as e:
            print("[!] portal:", e)
    elif command in ("portal-url",):
        try:
            from modules.webview import ensure_portal_token, _cfg
            tok = ensure_portal_token()
            port = (_cfg().get("portal") or {}).get("port", 8791)
            print(f"http://127.0.0.1:{port}/?token={tok}")
        except Exception as e:
            print("[!] portal-url:", e)
    elif command in ("honey", "honeyauth"):
        try:
            from modules.honeyauth import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] honey:", e)
    elif command in ("crypto-status",):
        try:
            from modules.crypto_store import status, ensure_key
            ensure_key()
            print(status())
        except Exception as e:
            print("[!] crypto:", e)
    elif command in ("encrypt-store",):
        try:
            from modules.crypto_store import write_encrypted_json, read_encrypted_json
            from pathlib import Path as P
            p = P.home() / ".sentinel/data/secure_sample.json.enc"
            write_encrypted_json(p, {"ok": True, "note": "sentinel encrypted store"})
            print({"wrote": str(p), "read_back": read_encrypted_json(p)})
        except Exception as e:
            print("[!] encrypt-store:", e)
    elif command in ("protect-pdf",):
        try:
            import sys as _sys
            from pathlib import Path as P
            from modules.crypto_store import protect_pdf
            args = _sys.argv[2:]
            src = P(args[0]) if args else P.home() / "Sentinel_Report.pdf"
            pw = args[1] if len(args) > 1 else "TrinTech"
            print(protect_pdf(src, pw))
        except Exception as e:
            print("[!] protect-pdf:", e)
    elif command in ("suppress", "suppressions"):
        try:
            from modules.suppressions import print_rules
            print_rules()
        except Exception as e:
            print("[!] suppress:", e)
    elif command in ("suppress-add",):
        try:
            import sys as _sys
            from modules.suppressions import add_suppression
            a = _sys.argv[2:]
            if len(a) < 2:
                print("Usage: sentinel suppress-add <detection_type> <pattern>")
            else:
                print(add_suppression(a[0], a[1], note="manual"))
        except Exception as e:
            print("[!] suppress-add:", e)
    elif command in ("suppress-del",):
        try:
            import sys as _sys
            from modules.suppressions import remove_rule
            rid = _sys.argv[2] if len(_sys.argv) > 2 else ""
            print({"removed": remove_rule(rid), "id": rid})
        except Exception as e:
            print("[!] suppress-del:", e)
'''

HUNT_EXTRA = r'''
            try:
                from modules.honeyauth import check as _honey_c
                from modules.attack_map import tag_alert
                from modules.suppressions import filter_events
                _hr = _honey_c()
                for _ev in filter_events(_hr.get("events") or [])[:5]:
                    _ev = tag_alert(_ev)
                    _msg = f"HONEY_AUTH: {_ev.get('username')} {_ev.get('detail','')[:120]}"
                    try:
                        logger.warning(_msg)
                    except Exception:
                        print("[!]", _msg)
            except Exception:
                pass
'''

def main():
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        sys.exit(1)
    src = ENGINE.read_text()

    if "portal-url" not in src:
        for a in [
            'elif command == "uninstall":',
            'elif command == "pdf"',
            'elif command in ("doctor"',
            'elif command in ("drift-pdf"',
            "Unknown command",
        ]:
            if a in src:
                src = src.replace(a, CLI + "\n    " + a, 1)
                print("[+] portal + harden CLI")
                break
        else:
            print("[!] CLI anchor missing")
    else:
        print("[=] portal CLI present")

    if "modules.honeyauth" not in src:
        idx = src.find("Persistence hunting")
        wt = src.find("while True:", idx if idx >= 0 else 0)
        if wt >= 0:
            end = wt + len("while True:")
            src = src[:end] + HUNT_EXTRA + src[end:]
            print("[+] hunt honeyauth hook")
        else:
            print("[!] no hunt loop")
    else:
        print("[=] honey hunt present")

    ENGINE.write_text(src)
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] wire_portal_harden OK")

if __name__ == "__main__":
    main()
