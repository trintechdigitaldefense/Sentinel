#!/usr/bin/env python3
"""Wire Phase 6 CLI (service-install, digest-cron) + ensure hunt heartbeat (indent-safe)."""
from __future__ import annotations
import py_compile
import re
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent / "sentinel.py"
ROOT = Path(__file__).resolve().parent

HYGIENE = """
    try:
        from modules.phase5 import hygiene_should_emit
        _hy = hygiene_should_emit(str(alert_type), None)
        if not _hy.get("allow", True):
            return
    except Exception:
        pass
"""


def _cli_block() -> str:
    root, engine = str(ROOT), str(ENGINE)
    return f"""
    elif command in ("service-install", "install-service"):
        try:
            from modules.phase5 import service_install
            print(service_install())
        except Exception:
            try:
                import os, textwrap
                unit = textwrap.dedent(\"\"\"
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
                \"\"\").strip() + "\\n"
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
    elif command in ("digest-cron", "schedule-digest"):
        try:
            from modules.phase5 import install_digest_cron
            sch = "weekly" if "--weekly" in args else "daily"
            print(install_digest_cron(sch))
        except Exception as e:
            print("[!] digest-cron:", e)
"""


def _body_indent_of_while(src: str, while_pos: int):
    line_start = src.rfind("\n", 0, while_pos) + 1
    line_end = src.find("\n", while_pos)
    if line_end < 0:
        line_end = len(src)
    while_line = src[line_start:line_end]
    while_indent = len(while_line) - len(while_line.lstrip(" "))
    return " " * (while_indent + 4), line_end


def inject_hunt_heartbeat(src: str):
    if "heartbeat_from_hunt" in src:
        return src, "present"
    idx = src.find("Persistence hunting")
    search_from = idx if idx >= 0 else 0
    wt = src.find("while True:", search_from)
    if wt < 0:
        wt = src.find("while True:")
    if wt < 0:
        return src, "missing"
    body_pad, line_end = _body_indent_of_while(src, wt)
    inner = body_pad + "    "
    snip = (
        f"\n{body_pad}try:\n"
        f"{inner}from modules.phase5 import heartbeat_from_hunt\n"
        f"{inner}heartbeat_from_hunt()\n"
        f"{body_pad}except Exception:\n"
        f"{inner}pass\n"
    )
    return src[:line_end] + snip + src[line_end:], "injected"


def main() -> int:
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        return 1
    src = ENGINE.read_text()
    CLI = _cli_block()

    if "service-install" not in src:
        for a in (
            '    elif command == "uninstall":',
            '    elif command in ("pdf", "report-pdf"):',
            "Unknown command",
        ):
            if a in src:
                src = src.replace(a, CLI + "\n" + a, 1)
                print("[+] Phase 6 CLI inserted")
                break
        else:
            print("[!] Phase 6 CLI anchor missing")
    else:
        print("[=] Phase 6 CLI present")

    src, st = inject_hunt_heartbeat(src)
    mark = "+" if st == "injected" else ("=" if st == "present" else "!")
    print(f"[{mark}] Hunt heartbeat {st}")

    if "hygiene_should_emit" not in src:
        m = re.search(r"def send_alert\s*\([^)]*\):\n", src)
        if m:
            src = src[: m.end()] + HYGIENE + src[m.end() :]
            print("[+] Hygiene gate in send_alert")
        else:
            print("[!] send_alert not found")
    else:
        print("[=] Hygiene present")

    needle = '("12", "Status", ("status",)),'
    if needle in src and "Always-on" not in src:
        inject = (
            needle
            + '\n        ("13", "Always-on service (systemd)", ("service-install",)),'
            + '\n        ("14", "Service status", ("service-status",)),'
            + '\n        ("15", "Schedule WhatsApp digest (daily cron)", ("digest-cron",)),'
        )
        src = src.replace(needle, inject, 1)
        print("[+] Menu items 13-15 added")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
    except Exception as e:
        print("[!] Syntax failed:", e)
        return 1
    print("[+] Syntax OK — Phase 6 wired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
