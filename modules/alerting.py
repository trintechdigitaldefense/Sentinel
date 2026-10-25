# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multi-channel alerting engine with deduplication (feature 5)."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import smtplib
import socket
import time
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.alerting")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _dedup_path() -> Path:
    return _home() / "data" / "alert_dedup.json"


def _load_dedup() -> dict:
    p = _dedup_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_dedup(d: dict) -> None:
    p = _dedup_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d))


def _fingerprint(severity: str, title: str, detail: str) -> str:
    raw = f"{severity}|{title}|{detail[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AlertEngine:
    def __init__(self, alerting_cfg: dict):
        self.cfg = alerting_cfg or {}
        self.dedup_minutes = int(self.cfg.get("dedup_minutes") or 15)

    def should_send(self, fp: str) -> tuple[bool, int]:
        """Return (send?, collapsed_count)."""
        store = _load_dedup()
        now = time.time()
        window = self.dedup_minutes * 60
        entry = store.get(fp)
        if not entry:
            store[fp] = {"ts": now, "count": 1}
            _save_dedup(store)
            return True, 1
        age = now - float(entry.get("ts") or 0)
        if age > window:
            store[fp] = {"ts": now, "count": 1}
            _save_dedup(store)
            return True, 1
        entry["count"] = int(entry.get("count") or 1) + 1
        store[fp] = entry
        _save_dedup(store)
        return False, entry["count"]

    def send(self, severity: str, title: str, detail: str = "", meta: Optional[dict] = None) -> dict:
        severity = (severity or "INFO").upper()
        meta = meta or {}
        fp = _fingerprint(severity, title, detail)
        send, count = self.should_send(fp)
        result = {"ok": True, "sent": False, "deduped": not send, "count": count, "channels": []}
        if not send:
            log.info("alert deduped x%s: %s %s", count, severity, title)
            result["ok"] = True
            return result

        body = f"[{severity}] {title}\n{detail}\n"
        if count > 1:
            body += f"\n(Repeated {count} times within dedup window)\n"
        body += f"\nHost: {socket.gethostname()}\nTime: {datetime.now().isoformat()}\n"

        # Quiet hours
        qh = self.cfg.get("quiet_hours") or {}
        if qh.get("enabled") and severity not in ("HIGH", "CRITICAL"):
            log.info("quiet hours — suppressed non-critical: %s", title)
            result["channels"].append({"channel": "quiet_hours", "ok": True, "suppressed": True})
            return result

        # WhatsApp (CallMeBot style)
        wa = self.cfg.get("whatsapp") or {}
        if wa.get("enabled") and wa.get("phone") and wa.get("apikey"):
            try:
                msg = urllib.parse.quote(body[:800])
                url = (
                    f"https://api.callmebot.com/whatsapp.php?"
                    f"phone={wa['phone']}&text={msg}&apikey={wa['apikey']}"
                )
                urllib.request.urlopen(url, timeout=15)
                result["channels"].append({"channel": "whatsapp", "ok": True})
                result["sent"] = True
            except Exception as e:
                result["channels"].append({"channel": "whatsapp", "ok": False, "error": str(e)})

        # Email SMTP
        em = self.cfg.get("email") or {}
        if em.get("enabled") and em.get("smtp_server") and em.get("to_emails"):
            try:
                msg = MIMEText(body)
                msg["Subject"] = f"SENTINEL {severity}: {title}"
                msg["From"] = em.get("from_email") or "sentinel@localhost"
                msg["To"] = ", ".join(em["to_emails"])
                if em.get("use_tls", True):
                    s = smtplib.SMTP(em["smtp_server"], int(em.get("smtp_port") or 587), timeout=20)
                    s.starttls()
                else:
                    s = smtplib.SMTP(em["smtp_server"], int(em.get("smtp_port") or 25), timeout=20)
                if em.get("username"):
                    s.login(em["username"], em.get("password") or "")
                s.sendmail(msg["From"], em["to_emails"], msg.as_string())
                s.quit()
                result["channels"].append({"channel": "email", "ok": True})
                result["sent"] = True
            except Exception as e:
                result["channels"].append({"channel": "email", "ok": False, "error": str(e)})

        # Webhook (Slack/Teams compatible)
        wh = self.cfg.get("webhook") or {}
        if wh.get("enabled") and wh.get("url"):
            try:
                payload = json.dumps({
                    "text": body,
                    "severity": severity,
                    "title": title,
                    "meta": meta,
                }).encode()
                req = urllib.request.Request(
                    wh["url"], data=payload,
                    headers={"Content-Type": "application/json", **(wh.get("headers") or {})},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=15)
                result["channels"].append({"channel": "webhook", "ok": True})
                result["sent"] = True
            except Exception as e:
                result["channels"].append({"channel": "webhook", "ok": False, "error": str(e)})

        # Syslog
        sy = self.cfg.get("syslog") or {}
        if sy.get("enabled"):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                pri = 14  # user.notice
                line = f"<{pri}>SENTINEL {severity}: {title} {detail[:200]}"
                sock.sendto(line.encode(), (sy.get("address") or "127.0.0.1", int(sy.get("port") or 514)))
                sock.close()
                result["channels"].append({"channel": "syslog", "ok": True})
                result["sent"] = True
            except Exception as e:
                result["channels"].append({"channel": "syslog", "ok": False, "error": str(e)})

        # Always append to local alert log
        try:
            ap = _home() / "data" / "alerts.log"
            ap.parent.mkdir(parents=True, exist_ok=True)
            rec = {
                "ts": datetime.now().isoformat(),
                "severity": severity,
                "title": title,
                "detail": detail[:500],
                "meta": meta,
                "fp": fp,
            }
            with open(ap, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass


        # SIEM / centralized logging
        try:
            from modules import siem as _siem
            siem_cfg = (self.cfg.get("siem") or {})
            if siem_cfg.get("enabled"):
                sr = _siem.emit(severity, title, detail, meta=meta, cfg=siem_cfg)
                result["channels"].extend(sr.get("channels") or [])
                if sr.get("sent"):
                    result["sent"] = True
                result["siem"] = {"ok": sr.get("ok"), "sent": sr.get("sent")}
        except Exception as e:
            result["channels"].append({"channel": "siem", "ok": False, "error": str(e)})

        # Offline queue: if no channel delivered, persist for later flush

        if not result.get("sent"):
            failed = [c for c in result.get("channels") or [] if not c.get("ok") and not c.get("suppressed")]
            if failed or not result.get("channels"):
                try:
                    from modules.phase4 import offline_enqueue
                    offline_enqueue(
                        title,
                        {"severity": severity, "detail": detail[:500], "meta": meta, "channels_failed": failed},
                    )
                    result["queued_offline"] = True
                except Exception as e:
                    result["queued_offline"] = False
                    result["queue_error"] = str(e)

        log.info("alert %s: %s channels=%s", severity, title, result["channels"])
        return result


# lazy import urllib.parse used above
import urllib.parse  # noqa: E402
