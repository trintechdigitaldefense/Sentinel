# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Multi-channel alerting engine with deduplication (feature 5)."""
from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import smtplib
import socket
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sentinel.alerting")


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _dedup_path() -> Path:
    return _home() / "data" / "alert_dedup.json"


# Per-path thread locks complement flock's cross-process protection.
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, Any] = {}


@contextmanager
def _exclusive_lock(lock_path: Path):
    """Acquire a thread-safe and process-safe exclusive file lock."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    key = str(lock_path.absolute())

    with _LOCKS_GUARD:
        thread_lock = _LOCKS.setdefault(key, threading.Lock())

    with thread_lock:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _dedup_lock_path() -> Path:
    return _dedup_path().with_name("alert_dedup.json.lock")


def _load_dedup_unlocked() -> dict:
    p = _dedup_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log.debug("dedup load failed: %s", e)
        return {}


def _save_dedup_unlocked(d: dict) -> None:
    p = _dedup_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{p.name}.",
        suffix=".tmp",
        dir=str(p.parent),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(d, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(tmp_name, p)

        try:
            dir_fd = os.open(str(p.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass



def _load_dedup() -> dict:
    with _exclusive_lock(_dedup_lock_path()):
        return _load_dedup_unlocked()


def _save_dedup(d: dict) -> None:
    with _exclusive_lock(_dedup_lock_path()):
        _save_dedup_unlocked(d)


def normalize_alerting_config(alerting_cfg: Optional[dict]) -> dict:
    """Normalize legacy Sentinel email settings for the unified router."""
    normalized = dict(alerting_cfg or {})
    email_cfg = normalized.get("email")

    if not isinstance(email_cfg, dict):
        return normalized

    email_cfg = dict(email_cfg)
    recipients = email_cfg.get("to_emails") or email_cfg.get("to_email") or []

    if isinstance(recipients, str):
        recipients = recipients.replace(";", ",").split(",")
    elif not isinstance(recipients, (list, tuple, set)):
        recipients = []

    clean_recipients = []
    for recipient in recipients:
        address = str(recipient).strip()
        if address and address not in clean_recipients:
            clean_recipients.append(address)

    email_cfg["to_emails"] = clean_recipients
    email_cfg["username"] = (
        email_cfg.get("username") or email_cfg.get("from_email") or ""
    )
    email_cfg["password"] = (
        email_cfg.get("password") or email_cfg.get("app_password") or ""
    )

    normalized["email"] = email_cfg
    return normalized


def _fingerprint(severity: str, title: str, detail: str) -> str:
    raw = f"{severity}|{title}|{detail[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AlertEngine:
    def __init__(self, alerting_cfg: dict):
        self.cfg = alerting_cfg or {}
        configured_window = self.cfg.get("dedup_minutes")
        self.dedup_minutes = int(
            15 if configured_window is None else configured_window
        )

    def should_send(self, fp: str) -> tuple[bool, int]:
        """Check deduplication without marking an undelivered alert handled."""
        store = _load_dedup()
        entry = store.get(fp)
        if not entry:
            return True, 1

        now = time.time()
        window = self.dedup_minutes * 60
        age = now - float(entry.get("ts") or 0)
        if age > window:
            return True, 1

        return False, int(entry.get("count") or 1) + 1

    def mark_handled(self, fp: str, count: int) -> None:
        """Persist handled state using an atomic locked read-modify-write."""
        with _exclusive_lock(_dedup_lock_path()):
            store = _load_dedup_unlocked()
            store[fp] = {
                "ts": time.time(),
                "count": max(1, int(count)),
            }
            _save_dedup_unlocked(store)

    def send(self, severity: str, title: str, detail: str = "", meta: Optional[dict] = None) -> dict:
        """Serialize delivery attempts for the same alert fingerprint."""
        severity = (severity or "INFO").upper()
        meta = meta or {}
        fp = _fingerprint(severity, title, detail)
        lock_path = (
            _home() / "data" / f"alert_delivery_{fp}.lock"
        )

        with _exclusive_lock(lock_path):
            return self._send_locked(severity, title, detail, meta)

    def send_queued(self, alert_type: str, details: Optional[dict] = None) -> dict:
        """Retry a queued alert without deduplication or re-enqueueing."""
        if not isinstance(details, dict):
            return {
                "ok": False,
                "sent": False,
                "error": "Invalid queued alert details",
                "channels": [],
            }

        severity = str(details.get("severity") or "MEDIUM").upper()
        title = str(alert_type or "QUEUED_ALERT")
        detail = str(details.get("detail") or details.get("raw") or "")
        meta = details.get("meta")
        if not isinstance(meta, dict):
            meta = {}

        fp = _fingerprint(severity, title, detail)
        lock_path = _home() / "data" / f"alert_delivery_{fp}.lock"

        with _exclusive_lock(lock_path):
            return self._send_locked(
                severity,
                title,
                detail,
                meta,
                bypass_dedup=True,
                queue_if_failed=False,
            )

    def _send_locked(
        self,
        severity: str,
        title: str,
        detail: str = "",
        meta: Optional[dict] = None,
        *,
        bypass_dedup: bool = False,
        queue_if_failed: bool = True,
    ) -> dict:
        severity = (severity or "INFO").upper()
        meta = meta or {}
        fp = _fingerprint(severity, title, detail)
        send, count = (True, 1) if bypass_dedup else self.should_send(fp)
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
            result["suppressed"] = True
            if not bypass_dedup:
                self.mark_handled(fp, count)
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
        except Exception as e:
            log.warning("alert log append failed: %s", e)


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

        if queue_if_failed and not result.get("sent"):
            failed = [c for c in result.get("channels") or [] if not c.get("ok") and not c.get("suppressed")]
            if failed or not result.get("channels"):
                try:
                    from modules.phase4 import offline_enqueue
                    queue_result = offline_enqueue(
                        title,
                        {"severity": severity, "detail": detail[:500], "meta": meta, "channels_failed": failed},
                    )
                    if queue_result is True or (
                        isinstance(queue_result, dict) and queue_result.get("ok") is True
                    ):
                        result["queued_offline"] = True
                    else:
                        result["queued_offline"] = False
                        result["queue_error"] = "offline queue did not confirm persistence"
                except Exception as e:
                    result["queued_offline"] = False
                    result["queue_error"] = str(e)

        handled = bool(result.get("sent") or result.get("queued_offline"))
        result["ok"] = handled
        if handled and not bypass_dedup:
            self.mark_handled(fp, count)

        log.info("alert %s: %s channels=%s", severity, title, result["channels"])
        return result


# lazy import urllib.parse used above
import urllib.parse  # noqa: E402


# Backward-compatible name used by sentinel.py.
AlertRouter = AlertEngine
