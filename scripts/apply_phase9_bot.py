#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Inject CASES / DIGEST bot commands into modules/bot.py."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "modules" / "bot.py"


def main() -> int:
    if not BOT.exists():
        print("[!] missing bot.py")
        return 1
    text = BOT.read_text(encoding="utf-8")
    original = text
    if "CASES — open cases" not in text and "SNAPSHOT — evidence capture" in text:
        text = text.replace(
            "SNAPSHOT — evidence capture\n",
            "SNAPSHOT — evidence capture\n"
            "CASES — open cases digest\n"
            "DIGEST — send open-cases to channels\n",
            1,
        )
    if 'up in ("CASES"' not in text:
        marker = '    return "Unknown command. Send HELP for list."'
        inject = (
            '    if up in ("CASES", "/CASES", "CASE", "/CASE"):\n'
            "        try:\n"
            "            from modules.msp_digest import format_digest\n"
            "            return format_digest()\n"
            "        except Exception as e:\n"
            '            return f"CASES error: {e}"\n'
            '    if up in ("DIGEST", "/DIGEST"):\n'
            "        try:\n"
            "            from modules.msp_digest import send_digest\n"
            '            r = send_digest(via="auto")\n'
            '            if r.get("ok"):\n'
            '                return "Digest sent.\\n" + (r.get("text") or "")[:1500]\n'
            '            return "Digest attempted.\\n" + str(r)[:1500]\n'
            "        except Exception as e:\n"
            '            return f"DIGEST error: {e}"\n'
            '    return "Unknown command. Send HELP for list."\n'
        )
        if marker in text:
            text = text.replace(marker, inject, 1)
    if text == original:
        print("[=] bot already wired")
        return 0
    BOT.write_text(text, encoding="utf-8")
    print(f"[+] updated {BOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
