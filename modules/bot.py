#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""FEATURE 03 — Two-way Telegram bot: STATUS / ACK / SNAPSHOT / DRIFT / DEADMAN."""
from __future__ import annotations
import json
import os
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

API = "https://api.telegram.org"

def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def bot_config() -> dict:
    c = _cfg()
    tg = (c.get("alerting") or {}).get("telegram") or c.get("telegram") or {}
    return {
        "enabled": bool(tg.get("enabled")),
        "token": tg.get("token") or tg.get("bot_token") or "",
        "chat_id": str(tg.get("chat_id") or tg.get("allowed_chat_id") or ""),
        "offset_file": _data() / "telegram_offset.json",
        "acked_file": _data() / "acked.json",
    }

def _http_json(url: str, data: Optional[dict] = None, timeout: int = 30) -> dict:
    body = None
    headers = {}
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or "{}")

def send_message(text: str, chat_id: Optional[str] = None) -> dict:
    cfg = bot_config()
    if not cfg["token"]:
        return {"ok": False, "error": "no telegram token in config"}
    chat_id = chat_id or cfg["chat_id"]
    if not chat_id:
        return {"ok": False, "error": "no chat_id"}
    url = f"{API}/bot{cfg['token']}/sendMessage"
    try:
        r = _http_json(url, {"chat_id": chat_id, "text": text[:4000]})
        return {"ok": bool(r.get("ok")), "result": r}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _load_acked() -> set:
    p = bot_config()["acked_file"]
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text())
        return set(str(x) for x in (data if isinstance(data, list) else data.get("ids", [])))
    except Exception:
        return set()

def _save_acked(ids: set) -> None:
    bot_config()["acked_file"].write_text(json.dumps(sorted(ids), indent=2))

def ack_alert(alert_id: str) -> dict:
    ids = _load_acked()
    ids.add(str(alert_id))
    _save_acked(ids)
    return {"ok": True, "acked": str(alert_id), "total_acked": len(ids)}

def is_acked(alert_id: str) -> bool:
    return str(alert_id) in _load_acked()

def _status_text() -> str:
    lines = [f"SENTINEL STATUS · {datetime.now().strftime('%Y-%m-%d %H:%M')}"]
    try:
        from modules.drift import trend
        t = trend()
        lines.append(f"Drift: {t.get('latest_score')}% intact · {str(t.get('verdict', ''))[:120]}")
    except Exception as e:
        lines.append(f"Drift: n/a ({e})")
    try:
        from modules.deadman import check_local, check_fleet
        loc = check_local()
        fl = check_fleet()
        lines.append(f"Heartbeat: {loc.get('status')} ({loc.get('detail', '')})")
        lines.append(f"Fleet: {len(fl.get('alive') or [])} alive / {len(fl.get('offline') or [])} offline")
        if fl.get("alert"):
            lines.append(fl["alert"])
    except Exception as e:
        lines.append(f"Deadman: n/a ({e})")
    alerts_log = _data() / "alerts.log"
    open_n = 0
    if alerts_log.exists():
        try:
            open_n = sum(1 for _ in alerts_log.open() if _.strip())
        except Exception:
            pass
    lines.append(f"Alert log lines: ~{open_n}")
    lines.append("Commands: STATUS | DRIFT | DEADMAN | ACK <id> | SNAPSHOT | HELP")
    return "\n".join(lines)

def _snapshot() -> str:
    folder = _data() / f"evidence_bot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    folder.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("alerts.log", "heartbeat.json", "drift_history.json", "acked.json"):
        src = _data() / name
        if src.exists():
            dest = folder / name
            dest.write_bytes(src.read_bytes())
            copied.append(name)
    return f"SNAPSHOT saved → {folder}\nFiles: {', '.join(copied) or 'none'}"

def handle_command(text: str, chat_id: str = "") -> str:
    text = (text or "").strip()
    up = text.upper()
    if up in ("STATUS", "/STATUS", "HELP", "/HELP", "/START"):
        if up in ("HELP", "/HELP", "/START"):
            return (
                "SENTINEL bot commands:\n"
                "STATUS — drift + heartbeat + alerts\n"
                "DRIFT — baseline drift report\n"
                "DEADMAN — sensor offline check\n"
                "ACK <id> — acknowledge alert id\n"
                "SNAPSHOT — evidence capture\n"
            )
        return _status_text()
    if up in ("DRIFT", "/DRIFT"):
        try:
            from modules.drift import trend
            t = trend()
            return f"DRIFT\nScore: {t.get('latest_score')}%\nDelta: {t.get('delta')}\n{t.get('verdict')}"
        except Exception as e:
            return f"DRIFT error: {e}"
    if up in ("DEADMAN", "/DEADMAN"):
        try:
            from modules.deadman import check_local, check_fleet
            loc = check_local()
            fl = check_fleet()
            msg = f"DEADMAN\nLocal: {loc.get('status')} — {loc.get('detail')}\n"
            msg += f"Fleet offline: {len(fl.get('offline') or [])}\n"
            if fl.get("alert"):
                msg += fl["alert"]
            return msg
        except Exception as e:
            return f"DEADMAN error: {e}"
    if up.startswith("ACK ") or up.startswith("/ACK "):
        parts = text.split(None, 1)
        if len(parts) < 2:
            return "Usage: ACK <alert_id>"
        r = ack_alert(parts[1].strip())
        return f"Acknowledged {r['acked']} (total acked: {r['total_acked']})"
    if up in ("SNAPSHOT", "/SNAPSHOT"):
        return _snapshot()
    return "Unknown command. Send HELP for list."

def poll_once() -> dict:
    cfg = bot_config()
    if not cfg["enabled"] or not cfg["token"]:
        return {"ok": False, "error": "telegram bot disabled or no token"}
    offset = 0
    of = cfg["offset_file"]
    if of.exists():
        try:
            offset = int(json.loads(of.read_text()).get("offset", 0))
        except Exception:
            offset = 0
    url = f"{API}/bot{cfg['token']}/getUpdates?timeout=25&offset={offset}"
    try:
        data = _http_json(url, timeout=35)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    results = data.get("result") or []
    handled = 0
    for upd in results:
        offset = max(offset, int(upd.get("update_id", 0)) + 1)
        msg = upd.get("message") or upd.get("edited_message") or {}
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id") or "")
        text = msg.get("text") or ""
        if cfg["chat_id"] and chat_id and chat_id != cfg["chat_id"]:
            continue
        if not text:
            continue
        reply = handle_command(text, chat_id)
        send_message(reply, chat_id=chat_id or cfg["chat_id"])
        handled += 1
    of.write_text(json.dumps({"offset": offset}))
    return {"ok": True, "handled": handled, "offset": offset}

def run_bot_loop(max_cycles: Optional[int] = None) -> None:
    cfg = bot_config()
    print(f"[*] Telegram bot loop enabled={cfg['enabled']} chat={cfg['chat_id'] or '?'}")
    if not cfg["enabled"] or not cfg["token"]:
        print("[!] Set alerting.telegram.enabled=true, token, chat_id in config.json")
        return
    n = 0
    while max_cycles is None or n < max_cycles:
        try:
            r = poll_once()
            if r.get("handled"):
                print(f"[+] handled {r['handled']} message(s)")
        except KeyboardInterrupt:
            print("\n[+] bot stopped")
            break
        except Exception as e:
            print(f"[!] bot cycle: {e}")
            time.sleep(5)
        n += 1

def ensure_bot_defaults() -> None:
    p = _home() / "config.json"
    c = {}
    if p.exists():
        try:
            c = json.loads(p.read_text())
        except Exception:
            c = {}
    al = c.setdefault("alerting", {})
    tg = al.setdefault("telegram", {})
    tg.setdefault("enabled", False)
    tg.setdefault("token", "")
    tg.setdefault("chat_id", "")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(c, indent=2))
