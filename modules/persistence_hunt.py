#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Persistence hunting — cron, systemd units/timers, RC files, authorized_keys, LD_PRELOAD.

Detects footholds that survive reboot: new timers, key drops, preload hijacks.
"""
from __future__ import annotations
import logging

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


def _data() -> Path:
    d = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def baseline_path() -> Path:
    return _data() / "persistence_baseline.json"


def _hash_file(p: Path) -> str:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except Exception:
        return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def snapshot() -> dict:
    """Full persistence surface snapshot."""
    entries: dict = {}

    # --- Cron ---
    for root in ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly"]:
        rp = Path(root)
        if rp.is_file():
            entries[str(rp)] = {"sha256": _hash_file(rp), "type": "cron"}
        elif rp.is_dir():
            for f in sorted(rp.glob("*")):
                if f.is_file() and not f.name.startswith("."):
                    entries[str(f)] = {"sha256": _hash_file(f), "type": "cron"}

    for spool in [Path("/var/spool/cron/crontabs"), Path("/var/spool/cron")]:
        try:
            if not spool.is_dir():
                continue
            for f in spool.iterdir():
                try:
                    if f.is_file():
                        entries[str(f)] = {"sha256": _hash_file(f), "type": "cron_user"}
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    # --- Systemd services + timers (timers increasingly favored over cron) ---
    for d in ["/etc/systemd/system", "/usr/lib/systemd/system",
              str(Path.home() / ".config/systemd/user")]:
        dp = Path(d)
        if not dp.is_dir():
            continue
        for pattern, typ in [("*.service", "systemd"), ("*.timer", "systemd_timer"),
                             ("*.socket", "systemd_socket")]:
            for f in sorted(dp.glob(pattern))[:120]:
                if f.is_file():
                    entries[str(f)] = {"sha256": _hash_file(f), "type": typ}

    # --- RC / profile scripts ---
    rc_paths = [
        Path("/etc/rc.local"),
        Path("/etc/profile"),
        Path("/etc/bash.bashrc"),
        Path.home() / ".bashrc",
        Path.home() / ".profile",
        Path.home() / ".zshrc",
        Path.home() / ".bash_profile",
        Path.home() / ".bash_login",
    ]
    for p in rc_paths:
        if p.exists() and p.is_file():
            entries[str(p)] = {"sha256": _hash_file(p), "type": "rc"}

    # /etc/profile.d fragments
    pd = Path("/etc/profile.d")
    if pd.is_dir():
        for f in sorted(pd.glob("*.sh"))[:40]:
            entries[str(f)] = {"sha256": _hash_file(f), "type": "profile_d"}

    # --- SSH authorized_keys (all home dirs + root) ---
    homes = [Path("/root")]
    home_root = Path("/home")
    if home_root.is_dir():
        try:
            homes.extend([p for p in home_root.iterdir() if p.is_dir()][:30])
        except (PermissionError, OSError):
            pass
    for home in homes:
        for keyfile in [home / ".ssh" / "authorized_keys", home / ".ssh" / "authorized_keys2"]:
            try:
                if not keyfile.exists():
                    continue
            except (PermissionError, OSError):
                continue
            # Also store line count for quick drift signal
            try:
                lines = [ln for ln in keyfile.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
                nkeys = len(lines)
            except (PermissionError, OSError):
                continue
            except Exception:
                nkeys = -1
            try:
                entries[str(keyfile)] = {
                    "sha256": _hash_file(keyfile),
                    "type": "authorized_keys",
                    "key_count": nkeys,
                }
            except (PermissionError, OSError):
                continue

    # --- LD_PRELOAD surface ---
    ld = Path("/etc/ld.so.preload")
    if ld.exists():
        try:
            entries[str(ld)] = {"sha256": _hash_file(ld), "type": "ld_preload", "content_preview": ld.read_text()[:200]}
        except (PermissionError, OSError):
            pass
    else:
        # Record absence so a future CREATE is detected
        entries["/etc/ld.so.preload"] = {"sha256": "", "type": "ld_preload", "absent": True}

    # Environment files that often carry LD_PRELOAD
    for envf in ["/etc/environment", "/etc/default/locale"]:
        ep = Path(envf)
        if ep.exists():
            entries[str(ep)] = {"sha256": _hash_file(ep), "type": "env_file"}

    return entries


def create_baseline() -> dict:
    snap = snapshot()
    baseline_path().write_text(json.dumps({
        "created": _now(),
        "count": len(snap),
        "entries": snap,
    }, indent=2))
    return {"ok": True, "count": len(snap), "path": str(baseline_path())}


def _check_locked(send_alert: Optional[Callable] = None, logger=None) -> dict:
    from modules.finding_state import newly_active, pending_active, mark_handled

    bp = baseline_path()
    if not bp.exists():
        create_baseline()
        newly_active("persistence", {})
        if logger:
            logger.info("Persistence baseline created (%s entries)", len(snapshot()))
        return {
            "ok": True, "needs_baseline": False,
            "events": [], "detail": "baseline created",
        }

    try:
        document = json.loads(bp.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("entries"), dict):
            raise ValueError("invalid persistence baseline structure")
        base = document["entries"]
        if any(not isinstance(path, str) or not isinstance(meta, dict)
               for path, meta in base.items()):
            raise ValueError("invalid persistence baseline entries")
    except Exception as exc:
        if logger:
            logger.error("Persistence baseline unreadable; preserving it: %s", exc)
        return {"ok": False, "events": [], "detail": "corrupt baseline"}

    cur = snapshot()
    candidates = {}
    fingerprints = {}
    extra_alerts = {}

    def add_candidate(event, fingerprint):
        key = f"{event['type']}:{event['path']}"
        candidates[key] = event
        encoded = json.dumps(
            fingerprint, sort_keys=True, separators=(",", ":"), default=str
        )
        fingerprints[key] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    for path, meta in cur.items():
        old = base.get(path)
        if not old:
            add_candidate(
                {
                    "type": "NEW_PERSISTENCE", "path": path,
                    "kind": meta.get("type"), "meta": meta,
                },
                meta,
            )
            continue

        if old.get("absent") and not meta.get("absent") and meta.get("sha256"):
            add_candidate(
                {"type": "LD_PRELOAD_CREATED", "path": path, "meta": meta},
                meta,
            )
            continue

        if old.get("sha256") and meta.get("sha256") and old["sha256"] != meta["sha256"]:
            kind = meta.get("type") or "file"
            alert_type = {
                "authorized_keys": "AUTHORIZED_KEYS_DRIFT",
                "ld_preload": "LD_PRELOAD_CHANGED",
                "systemd_timer": "SYSTEMD_TIMER_CHANGED",
                "systemd": "SYSTEMD_UNIT_CHANGED",
                "cron": "CRON_CHANGED",
                "cron_user": "CRON_CHANGED",
                "rc": "RC_FILE_CHANGED",
            }.get(kind, "PERSISTENCE_CHANGED")

            add_candidate(
                {"type": alert_type, "path": path, "kind": kind},
                meta,
            )

            if kind == "authorized_keys":
                old_n = old.get("key_count", -1)
                new_n = meta.get("key_count", -1)
                if old_n >= 0 and new_n > old_n:
                    extra_key = f"AUTHORIZED_KEYS_ADDED:{path}"
                    encoded = json.dumps(
                        {
                            "sha256": meta.get("sha256"),
                            "old_count": old_n,
                            "new_count": new_n,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    fingerprints[extra_key] = hashlib.sha256(
                        encoded.encode("utf-8")
                    ).hexdigest()
                    extra_alerts[extra_key] = (
                        "AUTHORIZED_KEYS_ADDED",
                        {
                            "path": path,
                            "old_count": old_n,
                            "new_count": new_n,
                        },
                    )

    for path, old in base.items():
        if path not in cur and not old.get("absent"):
            add_candidate(
                {
                    "type": "REMOVED_PERSISTENCE",
                    "path": path,
                    "kind": old.get("type"),
                },
                old,
            )

    reportable = pending_active("persistence", fingerprints)
    events = []
    handled_keys = set()

    for key, event in candidates.items():
        if key not in reportable:
            continue
        events.append(event)
        if logger:
            logger.warning("%s: %s", event["type"], event["path"])
        if send_alert:
            try:
                details = {"path": event["path"]}
                if event.get("kind") is not None:
                    details["kind"] = event["kind"]
                outcome = send_alert(event["type"], details)
                if isinstance(outcome, dict) and outcome.get("ok") is True:
                    handled_keys.add(key)
            except Exception as exc:
                logging.getLogger("sentinel").debug("%s: %s", __name__, exc)

    for key, (alert_type, details) in extra_alerts.items():
        if key not in reportable or not send_alert:
            continue
        try:
            outcome = send_alert(alert_type, details)
            if isinstance(outcome, dict) and outcome.get("ok") is True:
                handled_keys.add(key)
        except Exception as exc:
            logging.getLogger("sentinel").debug("%s: %s", __name__, exc)

    mark_handled("persistence", fingerprints, handled_keys)
    return {"ok": True, "events": events, "count": len(events)}



def check(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Run persistence detection and notification as one locked workflow."""
    from modules.finding_state import locked

    with locked("persistence"):
        return _check_locked(send_alert, logger)


def status() -> dict:
    bp = baseline_path()
    live = len(snapshot())
    base_n = 0
    if bp.exists():
        try:
            base_n = int((json.loads(bp.read_text()) or {}).get("count") or 0)
        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)

    return {"ok": True, "baseline_exists": bp.exists(), "baseline_count": base_n, "live_count": live, "path": str(bp)}
