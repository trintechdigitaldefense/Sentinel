#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Apply Phase 7 cases wiring to sentinel.py (menu, command, send_alert hook).

Run from repo root:
  python3 scripts/apply_cases_wire.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = ROOT / "sentinel.py"


def main() -> int:
    if not SENTINEL.exists():
        print("sentinel.py not found")
        return 1
    text = SENTINEL.read_text(encoding="utf-8")
    original = text

    # version
    text = text.replace('__version__ = "3.1.0"', '__version__ = "3.2.0"', 1)

    # send_alert hook
    needle = '''    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(alert) + "\\n")
    except Exception:
        pass
    # Phase 1: auto-quarantine on critical alerts'''
    # tolerate single-backslash in source
    needle2 = (
        "    try:\n"
        "        with open(log_file, \"a\") as f:\n"
        "            f.write(json.dumps(alert) + \"\\n\")\n"
        "    except Exception:\n"
        "        pass\n"
        "    # Phase 1: auto-quarantine on critical alerts"
    )
    insert = (
        "    try:\n"
        "        with open(log_file, \"a\") as f:\n"
        "            f.write(json.dumps(alert) + \"\\n\")\n"
        "    except Exception:\n"
        "        pass\n"
        "    # Phase 7: auto-open case for high/critical engine alerts\n"
        "    try:\n"
        "        from modules.case_hooks import maybe_open_case_from_engine_alert\n"
        "        maybe_open_case_from_engine_alert(alert_type, details if isinstance(details, dict) else {\"raw\": details})\n"
        "    except Exception:\n"
        "        pass\n"
        "    # Phase 1: auto-quarantine on critical alerts"
    )
    if "maybe_open_case_from_engine_alert" not in text:
        if needle2 in text:
            text = text.replace(needle2, insert, 1)
        else:
            # fallback: search simpler marker
            marker = "    # Phase 1: auto-quarantine on critical alerts"
            if marker in text and "maybe_open_case_from_engine_alert" not in text:
                hook = (
                    "    # Phase 7: auto-open case for high/critical engine alerts\n"
                    "    try:\n"
                    "        from modules.case_hooks import maybe_open_case_from_engine_alert\n"
                    "        maybe_open_case_from_engine_alert(alert_type, details if isinstance(details, dict) else {\"raw\": details})\n"
                    "    except Exception:\n"
                    "        pass\n"
                    "    # Phase 1: auto-quarantine on critical alerts"
                )
                text = text.replace(marker, hook, 1)

    # menu items
    if '("16", "Cases' not in text:
        old_menu = (
            '        ("15", "Schedule WhatsApp digest (daily cron)", ("digest-cron",)),\n'
            '        ("0",  "Exit", ("__exit__",)),\n'
            '    ]'
        )
        new_menu = (
            '        ("15", "Schedule WhatsApp digest (daily cron)", ("digest-cron",)),\n'
            '        ("16", "Cases — list open", ("cases", "list")),\n'
            '        ("17", "Cases — create / triage submenu", ("__cases__",)),\n'
            '        ("0",  "Exit", ("__exit__",)),\n'
            '    ]\n\n'
            '    cases_items = [\n'
            '        ("1", "List open cases", ("cases", "list")),\n'
            '        ("2", "List all recent cases", ("cases", "list-all")),\n'
            '        ("3", "Create case (interactive)", ("cases", "create")),\n'
            '        ("4", "Set status on a case", ("cases", "status")),\n'
            '        ("5", "Assign a case", ("cases", "assign")),\n'
            '        ("6", "Add note to a case", ("cases", "note")),\n'
            '        ("7", "Export evidence pack", ("cases", "evidence")),\n'
            '        ("8", "Show case detail", ("cases", "get")),\n'
            '        ("0", "Back to main menu", ("__back__",)),\n'
            '    ]'
        )
        if old_menu in text:
            text = text.replace(old_menu, new_menu, 1)

    # __cases__ loop handler
    if '"__cases__"' not in text:
        old_loop = (
            '            if args[0] == "__phase4__":\n'
            '                loop(p4_items, "PHASE 4 — Advanced tools")\n'
            '                continue\n'
            '            if args[0] == "__continuous__":'
        )
        new_loop = (
            '            if args[0] == "__phase4__":\n'
            '                loop(p4_items, "PHASE 4 — Advanced tools")\n'
            '                continue\n'
            '            if args[0] == "__cases__":\n'
            '                loop(cases_items, "CASES — Triage workflow")\n'
            '                continue\n'
            '            if args[0] == "__continuous__":'
        )
        if old_loop in text:
            text = text.replace(old_loop, new_loop, 1)

    # cases command — delegate to wire_cases
    if 'elif command == "cases":' not in text:
        marker = '    elif command == "clean":'
        handler = (
            '    elif command == "cases":\n'
            '        try:\n'
            '            from modules.wire_cases import cases_command\n'
            '            cases_command(args)\n'
            '        except Exception as e:\n'
            '            print(f"[!] cases unavailable: {e}")\n\n'
            '    elif command == "clean":'
        )
        if marker in text:
            text = text.replace(marker, handler, 1)

    # help line
    if 'cases' not in text[text.find('Show recent alerts'):text.find('Show recent alerts')+200] if 'Show recent alerts' in text else True:
        help_old = '        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}alerts{C.RESET}               Show recent alerts")'
        help_new = help_old + '\n        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}cases{C.RESET}                Case triage (list|create|status|...)")'
        if help_old in text and 'Case triage' not in text:
            text = text.replace(help_old, help_new, 1)

    if text == original:
        print("No changes applied (already wired or markers moved).")
        return 0

    SENTINEL.write_text(text, encoding="utf-8")
    print(f"Updated {SENTINEL}")
    print("Version, send_alert hook, menu 16/17, cases command applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
