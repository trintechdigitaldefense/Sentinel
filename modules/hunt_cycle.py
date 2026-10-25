# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Structured hunt cycle — ordered checks, isolated failures, cycle metrics.

Used by `sentinel hunt` and continuous protection so every loop does the same
defensive work: heartbeat → host checks → visibility → optional intel hooks.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _metrics_path() -> Path:
    return _data() / "hunt_metrics.json"


def load_metrics() -> dict:
    p = _metrics_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {
        "cycles": 0,
        "alerts_this_session": 0,
        "last_cycle_sec": None,
        "last_ok": None,
        "last_errors": [],
        "checks": {},
    }


def save_metrics(m: dict) -> None:
    _metrics_path().write_text(json.dumps(m, indent=2, default=str))


def _run_check(name: str, fn: Callable, errors: list, checks: dict) -> Any:
    t0 = time.monotonic()
    try:
        result = fn()
        checks[name] = {
            "ok": True,
            "ms": int((time.monotonic() - t0) * 1000),
        }
        return result
    except Exception as e:
        checks[name] = {
            "ok": False,
            "ms": int((time.monotonic() - t0) * 1000),
            "error": str(e)[:200],
        }
        errors.append(f"{name}: {e}")
        return None


def run_cycle(
    config: dict,
    logger=None,
    *,
    fim_check=None,
    process_scan=None,
    ssh_blocking_check=None,
    outbound_scan=None,
    user_monitor_check=None,
    cron_monitor_check=None,
    send_alert=None,
    include_optional_hooks: bool = True,
) -> dict:
    """Execute one full defensive hunt cycle."""
    t0 = time.monotonic()
    errors: list[str] = []
    checks: dict[str, Any] = {}
    cycle_alerts = []

    def _sa(t, d, *a, **k):
        cycle_alerts.append(t)
        if send_alert:
            return send_alert(t, d, logger)

    # 1. Heartbeat / deadman
    def _hb():
        try:
            from modules.phase5 import heartbeat_from_hunt
            heartbeat_from_hunt()
        except Exception:
            pass
        try:
            from modules.deadman import emit_heartbeat, check_fleet
            emit_heartbeat("hunt")
            check_fleet()
        except Exception:
            pass
        return True
    _run_check("heartbeat", _hb, errors, checks)

    # 2. Core host checks
    if fim_check:
        _run_check("fim", lambda: fim_check(config, logger), errors, checks)
    if process_scan:
        _run_check("processes", lambda: process_scan(config, logger), errors, checks)
    if ssh_blocking_check:
        _run_check("ssh_bruteforce", lambda: ssh_blocking_check(config, logger), errors, checks)
    if outbound_scan:
        _run_check("outbound", lambda: outbound_scan(config, logger), errors, checks)
    if user_monitor_check:
        _run_check("users", lambda: user_monitor_check(config, logger), errors, checks)
    if cron_monitor_check:
        _run_check("cron", lambda: cron_monitor_check(config, logger), errors, checks)

    # 3. Persistence surface
    def _per():
        from modules.persistence_hunt import check as per_check
        return per_check(send_alert=_sa, logger=logger)
    _run_check("persistence", _per, errors, checks)

    # 4. Visibility
    def _vis():
        from modules.visibility import inventory_devices, inventory_processes
        inventory_processes()
        return inventory_devices(send_alert=_sa, logger=logger)
    _run_check("visibility", _vis, errors, checks)

    # 5. Optional sensors (best-effort)
    if include_optional_hooks:
        optional = [
            ("usb", "modules.usb_watch"),
            ("lateral", "modules.lateral"),
            ("dns", "modules.dns_watch"),
            ("device_radar", "modules.device_radar"),
            ("ransomware_tripwire", "modules.ransomware_tripwire"),
            ("honeyauth", "modules.honeyauth"),
        ]
        for name, modpath in optional:
            def _make(mp=modpath):
                def _fn():
                    import importlib
                    mod = importlib.import_module(mp)
                    return mod.check()
                return _fn
            _run_check(name, _make(), errors, checks)

    # 6. Expire SSH blocks / offline flush light
    def _maint():
        try:
            from modules.brute_force import expire_blocks
            expire_blocks(logger=logger)
        except Exception:
            pass
        try:
            from modules.phase4 import offline_flush
            offline_flush()
        except Exception:
            pass
        return True
    _run_check("maintenance", _maint, errors, checks)

    elapsed = time.monotonic() - t0
    metrics = load_metrics()
    metrics["cycles"] = int(metrics.get("cycles") or 0) + 1
    metrics["last_cycle_sec"] = round(elapsed, 2)
    metrics["last_ok"] = len(errors) == 0
    metrics["last_errors"] = errors[-10:]
    metrics["last_ts"] = datetime.now(timezone.utc).isoformat()
    metrics["checks"] = checks
    metrics["alerts_this_session"] = int(metrics.get("alerts_this_session") or 0) + len(cycle_alerts)
    metrics["last_alert_types"] = cycle_alerts[:20]
    save_metrics(metrics)

    if logger:
        ok_n = sum(1 for c in checks.values() if c.get("ok"))
        fail_n = len(checks) - ok_n
        logger.info(
            "Hunt cycle #%s — %.1fs · %s ok · %s fail · %s alerts",
            metrics["cycles"], elapsed, ok_n, fail_n, len(cycle_alerts),
        )
        for e in errors[:5]:
            logger.warning("  cycle error: %s", e)

    return {
        "ok": len(errors) == 0,
        "elapsed_sec": round(elapsed, 2),
        "checks": checks,
        "errors": errors,
        "alerts": cycle_alerts,
        "metrics": metrics,
    }
