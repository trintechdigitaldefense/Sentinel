#!/usr/bin/env python3
"""Safely wire missing CLI commands without touching the hunt loop."""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"

BLOCK = '''
    elif command in ("hygiene", "alert-hygiene"):
        try:
            from modules.phase5 import hygiene_status, hygiene_reset, ensure_hygiene_defaults
            ensure_hygiene_defaults()
            if args and args[0] in ("reset", "--reset"):
                print(hygiene_reset())
            print(hygiene_status())
        except Exception as e:
            print("[!] hygiene:", e)
    elif command in ("service-install", "install-service"):
        try:
            from modules.phase5 import service_install
            print(service_install())
        except Exception:
            try:
                import os, textwrap
                unit = textwrap.dedent(f"""
                [Unit]
                Description=SENTINEL persistence hunt
                After=network.target
                [Service]
                Type=simple
                WorkingDirectory={root}
                ExecStart=/usr/bin/python3 {engine} hunt
                Restart=always
                RestartSec=10
                [Install]
                WantedBy=multi-user.target
                """).strip().format(root=str(ROOT), engine=str(ENGINE)) + "\\n"
                path = Path("/etc/systemd/system/sentinel-hunt.service")
                path.write_text(unit)
                os.system("systemctl daemon-reload")
                os.system("systemctl enable --now sentinel-hunt.service")
                print("[+] service sentinel-hunt installed/started (fallback)")
            except Exception as e2:
                print("[!] service-install:", e2)
    elif command in ("service-status",):
        try:
            import subprocess
            r = subprocess.run(["systemctl", "is-active", "sentinel-hunt"], capture_output=True, text=True)
            print(r.stdout.strip() or r.stderr.strip() or "unknown")
        except Exception as e:
            print("[!] service-status:", e)
'''


def main() -> int:
    if not ENGINE.exists():
        print("[!] no engine")
        return 1
    src = ENGINE.read_text()
    changed = False
    if 'command in ("hygiene"' not in src and 'command == "hygiene"' not in src:
        anchor = '    elif command == "uninstall":'
        if anchor not in src:
            anchor = '    else:\n        logger.error(f"{C.RED}✗ Unknown command:'
        if anchor not in src:
            print("[!] no CLI anchor")
            return 1
        src = src.replace(anchor, BLOCK + "\n" + anchor, 1)
        changed = True
        print("[+] hygiene + service-install CLI wired")
    else:
        print("[=] hygiene already present")
    if changed:
        ENGINE.write_text(src)
    import py_compile
    py_compile.compile(str(ENGINE), doraise=True)
    print("[+] Syntax OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
