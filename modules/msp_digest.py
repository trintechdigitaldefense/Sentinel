# © 2026 TrinTech Digital Defense — authorized defensive use only
"""MSP daily digest — open cases for WhatsApp / Telegram / text (Phase 9)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional


OPEN = ("new", "triaging", "investigating", "contained")


def collect_open_cases(limit: int = 25) -> list[dict]:
    from modules import cases

    rows: list[dict] = []
    for st in OPEN:
        rows.extend(cases.list_cases(status=st, limit=limit))
    rows = sorted(rows, key=lambda c: c.get("updated_at") or "", reverse=True)
    return rows[:limit]


def format_digest(cases_list: Optional[list[dict]] = None, host: str = "") -> str:
    rows = cases_list if cases_list is not None else collect_open_cases()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    host = host or _hostname()
    lines = [
        f"SENTINEL cases digest · {ts}",
        f"Host: {host}",
        f"Open: {len(rows)}",
        "",
    ]
    if not rows:
        lines.append("No open cases.")
        return "\n".join(lines)
    for c in rows:
        lines.append(
            f"• {c.get('id')} [{c.get('status')}/{c.get('severity')}] "
            f"{(c.get('title') or '')[:60]}"
        )
        if c.get("assignee"):
            lines.append(f"  → {c['assignee']}")
    lines.append("")
    lines.append("Reply in bot: CASES | or CLI: sentinel cases list")
    return "\n".join(lines)


def _hostname() -> str:
    try:
        import os

        return os.uname().nodename
    except Exception:
        return "host"


def send_digest(via: str = "auto") -> dict:
    """Send open-cases digest via Telegram bot and/or WhatsApp (CallMeBot).

    via: auto | telegram | whatsapp | both | none (format only)
    """
    text = format_digest()
    result = {"ok": True, "text": text, "channels": []}
    via = (via or "auto").lower()

    if via in ("none", "print", "format"):
        return result

    if via in ("auto", "telegram", "both", "bot"):
        try:
            from modules.bot import bot_config, send_message

            cfg = bot_config()
            if cfg.get("enabled") and cfg.get("token") and cfg.get("chat_id"):
                r = send_message(text)
                result["channels"].append({"channel": "telegram", "ok": r.get("ok", True), "detail": r})
            elif via in ("telegram", "bot"):
                result["channels"].append({"channel": "telegram", "ok": False, "error": "bot not configured"})
        except Exception as e:
            result["channels"].append({"channel": "telegram", "ok": False, "error": str(e)})

    if via in ("auto", "whatsapp", "both"):
        try:
            import json
            import os
            from pathlib import Path

            from modules.alerting import AlertEngine

            cfg_path = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
            alerting = {}
            if cfg_path.exists():
                alerting = json.loads(cfg_path.read_text()).get("alerting") or {}
            wa = alerting.get("whatsapp") or {}
            if wa.get("enabled") or (wa.get("phone") and wa.get("apikey")):
                eng = AlertEngine(alerting)
                r = eng.send("high", "SENTINEL open cases digest", text)
                result["channels"].append({"channel": "whatsapp", "ok": True, "detail": r})
            elif via == "whatsapp":
                result["channels"].append({"channel": "whatsapp", "ok": False, "error": "whatsapp not configured"})
        except Exception as e:
            result["channels"].append({"channel": "whatsapp", "ok": False, "error": str(e)})

    if result["channels"] and not any(c.get("ok") for c in result["channels"]):
        result["ok"] = False
    return result
