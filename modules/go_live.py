# © 2026 TrinTech Digital Defense — authorized defensive use only
"""One-shot operational setup per host: baselines + canaries + alert channel.

Usage (from CLI):
  python3 sentinel.py go-live
  python3 sentinel.py go-live --service
  python3 sentinel.py go-live --json

Does not replace pilot validation — run pilot/field-soak after go-live.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cfg_path() -> Path:
    return _home() / "config.json"


def _load_cfg() -> dict:
    p = _cfg_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _save_cfg(cfg: dict) -> None:
    p = _cfg_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2, default=str))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _step(results: list, name: str, ok: bool, **extra) -> dict:
    row = {"step": name, "ok": ok, **extra}
    results.append(row)
    return row


def ensure_alert_channel(cfg: dict) -> dict:
    """Ensure at least local SIEM ship file is on; report WhatsApp/email/Splunk state."""
    alerting = cfg.setdefault("alerting", {})
    siem = alerting.setdefault("siem", {})
    siem.setdefault("format", "json")
    siem.setdefault("min_severity", "LOW")
    siem["enabled"] = True
    sf = siem.setdefault("ship_file", {"enabled": True, "path": ""})
    sf["enabled"] = True
    siem.setdefault("syslog", siem.get("syslog") or {"enabled": False, "host": "", "port": 514, "protocol": "udp"})
    siem.setdefault(
        "splunk_hec",
        siem.get("splunk_hec")
        or {"enabled": False, "url": "", "token": "", "index": "", "verify_tls": True},
    )
    siem.setdefault("webhook", siem.get("webhook") or {"enabled": False, "url": "", "verify_tls": True})
    alerting["siem"] = siem
    cfg["alerting"] = alerting

    wa = alerting.get("whatsapp") or cfg.get("whatsapp") or {}
    email = alerting.get("email") or {}
    sp = siem.get("splunk_hec") or {}

    remote = bool(
        (wa.get("enabled") and (wa.get("phone") or wa.get("apikey")))
        or (email.get("enabled") and email.get("to_email"))
        or (sp.get("enabled") and sp.get("url") and sp.get("token"))
    )
    _save_cfg(cfg)
    return {
        "ok": True,
        "local_ship": True,
        "remote_channel": remote,
        "whatsapp": bool(wa.get("enabled")),
        "email": bool(email.get("enabled")),
        "splunk": bool(sp.get("enabled") and sp.get("url")),
        "hint": None
        if remote
        else "Add WhatsApp, email, or: python3 sentinel.py siem splunk-configure --url URL --token TOKEN",
    }


def run_go_live(
    config: Optional[dict] = None,
    logger=None,
    *,
    fim_build_fn: Optional[Callable] = None,
    deploy_deception_fn: Optional[Callable] = None,
    service_install: bool = False,
    service_install_fn: Optional[Callable] = None,
) -> dict:
    results: list[dict] = []
    cfg = config if config is not None else _load_cfg()
    if not cfg:
        cfg = _load_cfg()

    # 1. Directories + permissions
    try:
        for sub in ("data", "data/deception_artifacts", "data/integrity_baseline", "logs"):
            p = _home() / sub if not sub.startswith("data") else _data() / sub.replace("data/", "")
            if sub == "data":
                p = _data()
            elif sub == "logs":
                p = _home() / "logs"
            elif sub == "data/deception_artifacts":
                p = _data() / "deception_artifacts"
            elif sub == "data/integrity_baseline":
                p = _data() / "integrity_baseline"
            p.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(_home(), 0o700)
            os.chmod(_data(), 0o700)
        except Exception:
            pass
        _step(results, "directories", True, path=str(_home()))
    except Exception as e:
        _step(results, "directories", False, error=str(e))

    # 2. Alert channel (local ship always)
    try:
        ch = ensure_alert_channel(cfg)
        _step(results, "alert_channel", True, **{k: v for k, v in ch.items() if k != "ok"})
    except Exception as e:
        _step(results, "alert_channel", False, error=str(e))

    # 3. Persistence baseline
    try:
        from modules.persistence_hunt import create_baseline, baseline_path
        r = create_baseline()
        _step(results, "persistence_baseline", True, count=r.get("count"), path=str(baseline_path()))
    except Exception as e:
        _step(results, "persistence_baseline", False, error=str(e))

    # 4. SUID baseline
    try:
        from modules.fim_suid import build_baseline
        r = build_baseline()
        _step(results, "suid_baseline", True, count=r.get("count"))
    except Exception as e:
        _step(results, "suid_baseline", False, error=str(e))

    # 5. FIM baseline
    try:
        if fim_build_fn and logger is not None and config is not None:
            fim_build_fn(config, logger)
            fim_path = _data() / "integrity_baseline" / "integrity_baseline.json"
            n = 0
            if fim_path.exists():
                try:
                    n = len(json.loads(fim_path.read_text()))
                except Exception:
                    n = 1
            _step(results, "fim_baseline", True, files=n, path=str(fim_path))
        else:
            fim_path = _data() / "integrity_baseline" / "integrity_baseline.json"
            if fim_path.exists():
                _step(results, "fim_baseline", True, exists=True)
            else:
                _step(
                    results,
                    "fim_baseline",
                    False,
                    hint="python3 sentinel.py integrity",
                )
    except Exception as e:
        _step(results, "fim_baseline", False, error=str(e))

    # 6. Canaries / deception
    try:
        if deploy_deception_fn and logger is not None and config is not None:
            deploy_deception_fn(config, logger)
            dec = _data() / "deception_artifacts"
            n = sum(1 for p in dec.rglob("*") if p.is_file()) if dec.exists() else 0
            _step(results, "canaries", True, files=n)
        else:
            dec = _data() / "deception_artifacts"
            n = sum(1 for p in dec.rglob("*") if p.is_file()) if dec.exists() else 0
            _step(results, "canaries", n > 0, files=n, hint=None if n > 0 else "python3 sentinel.py deception")
    except Exception as e:
        _step(results, "canaries", False, error=str(e))

    # 7. Heartbeat
    try:
        from modules.phase5 import heartbeat_write
        heartbeat_write({"source": "go-live"})
        _step(results, "heartbeat", True)
    except Exception:
        try:
            from modules.deadman import emit_heartbeat
            emit_heartbeat("go-live")
            _step(results, "heartbeat", True)
        except Exception as e:
            _step(results, "heartbeat", False, error=str(e))

    # 8. Optional service
    if service_install:
        try:
            if service_install_fn:
                service_install_fn()
                _step(results, "service_install", True)
            else:
                from modules.phase5 import service_install as _si
                r = _si()
                _step(results, "service_install", bool(r.get("ok", True)), result=r)
        except Exception as e:
            _step(
                results,
                "service_install",
                False,
                error=str(e),
                hint="python3 sentinel.py service-install",
            )
    else:
        _step(
            results,
            "service_install",
            True,
            skipped=True,
            hint="python3 sentinel.py go-live --service   OR   service-install",
        )

    # 9. Seed critical store path
    try:
        from modules.critical_alerts import status as crit_status
        st = crit_status()
        _step(results, "critical_store", True, open=st.get("open_count", 0))
    except Exception as e:
        _step(results, "critical_store", False, error=str(e))

    hard_fail = [r for r in results if not r.get("ok") and not r.get("skipped")]
    out = {
        "ok": len(hard_fail) == 0,
        "ts": _now(),
        "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "steps": results,
        "next": [],
    }
    for r in results:
        if r.get("hint"):
            out["next"].append(r["hint"])
    out["next"].extend(
        [
            "python3 sentinel.py pilot",
            "python3 sentinel.py field-soak --confirm",
            "python3 sentinel.py dashboard-url",
        ]
    )
    # dedupe next
    seen = set()
    next_u = []
    for n in out["next"]:
        if n not in seen:
            seen.add(n)
            next_u.append(n)
    out["next"] = next_u

    path = _data() / "go_live_report.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    out["report_path"] = str(path)
    return out


def print_report(data: dict) -> None:
    print()
    print("=" * 60)
    print("  SENTINEL GO-LIVE (host operational setup)")
    print("=" * 60)
    for s in data.get("steps") or []:
        if s.get("skipped"):
            mark = "SKIP"
        else:
            mark = "OK" if s.get("ok") else "FAIL"
        line = f"  [{mark}] {s.get('step')}"
        if s.get("count") is not None:
            line += f"  count={s['count']}"
        if s.get("files") is not None:
            line += f"  files={s['files']}"
        if s.get("remote_channel") is not None:
            line += (
                f"  local_ship={s.get('local_ship')} remote={s.get('remote_channel')} "
                f"wa={s.get('whatsapp')} email={s.get('email')} splunk={s.get('splunk')}"
            )
        if s.get("error"):
            line += f"  ERR={s['error']}"
        print(line)
        if s.get("hint") and not s.get("ok"):
            print(f"        → {s['hint']}")
    print("-" * 60)
    print(f"  Ready: {'YES' if data.get('ok') else 'PARTIAL — see FAIL steps'}")
    print("  Next:")
    for n in (data.get("next") or [])[:6]:
        print(f"    · {n}")
    if data.get("report_path"):
        print(f"  Report: {data['report_path']}")
    print("=" * 60)
    print()
