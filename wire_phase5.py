#!/usr/bin/env python3
"""Wire Phase 5 CLI + hunt heartbeat + send_alert hygiene (indent-safe)."""
from __future__ import annotations
import py_compile
import re
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent / "sentinel.py"

CLI_BLOCK = '''
    elif command in ("phase5", "p5"):
        try:
            from modules.phase5 import phase5_self_check, heartbeat_write, ensure_hygiene_defaults, ensure_whatsapp_defaults
            ensure_hygiene_defaults()
            ensure_whatsapp_defaults()
            heartbeat_write({"source": "phase5"})
            print(phase5_self_check())
        except Exception as e:
            print("[!] phase5:", e)
    elif command == "autosubnet":
        try:
            from modules.phase5 import auto_subnet_apply
            print(auto_subnet_apply())
        except Exception as e:
            print("[!] autosubnet:", e)
    elif command == "heartbeat":
        try:
            from modules.phase5 import heartbeat_write, heartbeat_status
            print(heartbeat_write({"source": "cli"}))
            print(heartbeat_status())
        except Exception as e:
            print("[!] heartbeat:", e)
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
            print("[!] digest:", e)
    elif command in ("whatsapp-digest", "wa-digest", "digest-send"):
        try:
            from modules.phase5 import whatsapp_digest
            hours = 24
            force = "--force" in args
            if "--hours" in args:
                i = args.index("--hours")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(whatsapp_digest(hours=hours, force=force))
        except Exception as e:
            print("[!] whatsapp-digest:", e)
    elif command in ("hygiene", "alert-hygiene"):
        try:
            from modules.phase5 import hygiene_status, hygiene_reset, ensure_hygiene_defaults
            ensure_hygiene_defaults()
            if "--reset" in args or (args and args[0] == "reset"):
                print(hygiene_reset())
            print(hygiene_status())
        except Exception as e:
            print("[!] hygiene:", e)
'''

HYGIENE = '''
    try:
        from modules.phase5 import hygiene_should_emit
        _hy = hygiene_should_emit(str(alert_type), None)
        if not _hy.get("allow", True):
            return
    except Exception:
        pass
'''


def _body_indent_of_while(src: str, while_pos: int) -> tuple[str, int]:
    """Return (indent_str for body, end index of 'while True:' line)."""
    line_start = src.rfind("\n", 0, while_pos) + 1
    line_end = src.find("\n", while_pos)
    if line_end < 0:
        line_end = len(src)
    while_line = src[line_start:line_end]
    # count leading spaces on while line
    while_indent = len(while_line) - len(while_line.lstrip(" "))
    body_indent = while_indent + 4
    return " " * body_indent, line_end


def inject_hunt_heartbeat(src: str) -> tuple[str, str]:
    if "heartbeat_from_hunt" in src:
        return src, "present"
    # Prefer hunt command's while True (after "Persistence hunting")
    idx = src.find("Persistence hunting")
    search_from = idx if idx >= 0 else 0
    wt = src.find("while True:", search_from)
    if wt < 0:
        wt = src.find("while True:")
    if wt < 0:
        return src, "missing"
    body_pad, line_end = _body_indent_of_while(src, wt)
    inner = body_pad + "    "  # one more level inside try
    snip = (
        f"\n{body_pad}try:\n"
        f"{inner}from modules.phase5 import heartbeat_from_hunt\n"
        f"{inner}heartbeat_from_hunt()\n"
        f"{body_pad}except Exception:\n"
        f"{inner}pass\n"
    )
    # Insert right after the while True: line (before existing body)
    new = src[:line_end] + snip + src[line_end:]
    return new, "injected"


def inject_hygiene(src: str) -> tuple[str, str]:
    if "hygiene_should_emit" in src:
        return src, "present"
    m = re.search(r"def send_alert\s*\([^)]*\):\n", src)
    if not m:
        return src, "missing"
    return src[: m.end()] + HYGIENE + src[m.end() :], "injected"


def inject_cli(src: str) -> tuple[str, str]:
    if "whatsapp-digest" in src and "phase5" in src:
        return src, "present"
    for a in (
        '    elif command == "uninstall":',
        '    elif command in ("pdf", "report-pdf"):',
        '    elif command == "pdf"',
        "Unknown command",
    ):
        if a in src:
            return src.replace(a, CLI_BLOCK + "\n" + a, 1), "inserted"
    return src, "missing"


def main() -> int:
    if not ENGINE.exists() or ENGINE.stat().st_size < 1000:
        print("[!] sentinel.py missing — run setup.py first")
        return 1
    src = ENGINE.read_text()

    src, st = inject_cli(src)
    print(f"[{'+' if st == 'inserted' else '=' if st == 'present' else '!'}] CLI {st}")

    src, st = inject_hunt_heartbeat(src)
    print(f"[{'+' if st == 'injected' else '=' if st == 'present' else '!'}] Hunt heartbeat {st}")

    src, st = inject_hygiene(src)
    print(f"[{'+' if st == 'injected' else '=' if st == 'present' else '!'}] Hygiene {st}")

    ENGINE.write_text(src)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
    except Exception as e:
        print("[!] Syntax failed:", e)
        return 1
    print("[+] Syntax OK — Phase 5 wired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
