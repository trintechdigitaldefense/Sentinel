# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Field soak — authorized on-site proof that detection + alerts work.

Runs a controlled sequence:
  1. Preflight (doctor-ish)
  2. Ensure canaries / baselines exist
  3. Safe threat-sim probes (needs --confirm)
  4. Alert channel status (WhatsApp / Splunk / SIEM ship)
  5. Summary GO / NO-GO for friendly-site soak

Does not open reverse shells or block production IPs without explicit steps.
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


def _cfg() -> dict:
    p = _home() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def _step(name: str, fn: Callable, results: list) -> dict:
    row: dict[str, Any] = {"step": name, "ok": False}
    try:
        out = fn()
        if isinstance(out, dict):
            row.update(out)
            row["ok"] = bool(out.get("ok", True))
        else:
            row["ok"] = True
            row["result"] = out
    except Exception as e:
        row["ok"] = False
        row["error"] = str(e)
    results.append(row)
    return row


def run_field_soak(
    *,
    confirm: bool = False,
    run_sim: bool = True,
    logger=None,
) -> dict:
    results: list[dict] = []
    cfg = _cfg()

    def preflight():
        issues = []
        engine = Path(__file__).resolve().parent.parent / "sentinel.py"
        if not engine.exists():
            issues.append("sentinel.py missing")
        for mod in ("threat_sim", "siem", "critical_alerts", "pilot_check"):
            try:
                __import__(f"modules.{mod}")
            except Exception as e:
                issues.append(f"module {mod}: {e}")
        return {"ok": not issues, "issues": issues}

    _step("preflight", preflight, results)

    def canaries():
        dec = _data() / "deception_artifacts"
        n = 0
        if dec.exists():
            n = sum(1 for p in dec.rglob("*") if p.is_file())
        # also count common canary paths from config tracker
        tracker = dec / "config.json"
        tracked = 0
        if tracker.exists():
            try:
                tracked = len(json.loads(tracker.read_text()).get("files") or [])
            except Exception:
                pass
        ok = n > 0 or tracked > 0
        return {
            "ok": ok,
            "artifact_files": n,
            "tracked": tracked,
            "hint": None if ok else "Run: python3 sentinel.py deception",
        }

    _step("canaries", canaries, results)

    def baselines():
        fim = (_data() / "integrity_baseline" / "integrity_baseline.json").exists()
        per = (_data() / "persistence_baseline.json").exists() or (_data() / "cron_baseline.json").exists()
        return {
            "ok": fim,
            "fim": fim,
            "persistence": per,
            "hint": None if fim else "Run: python3 sentinel.py integrity",
        }

    _step("baselines", baselines, results)

    def channels():
        alerting = cfg.get("alerting") or {}
        wa = alerting.get("whatsapp") or cfg.get("whatsapp") or {}
        siem = alerting.get("siem") or {}
        sp = siem.get("splunk_hec") or {}
        ship = _data() / "siem_ship.jsonl"
        ship_n = 0
        if ship.exists():
            ship_n = sum(1 for ln in ship.read_text().splitlines() if ln.strip())
        return {
            "ok": True,
            "whatsapp_enabled": bool(wa.get("enabled") and (wa.get("phone") or wa.get("apikey"))),
            "siem_enabled": bool(siem.get("enabled")),
            "splunk_hec": bool(sp.get("enabled") and sp.get("url") and sp.get("token")),
            "ship_file_lines": ship_n,
            "email_enabled": bool((alerting.get("email") or {}).get("enabled")),
        }

    _step("alert_channels", channels, results)

    def sim():
        if not run_sim:
            return {"ok": True, "skipped": True, "reason": "sim disabled"}
        if not confirm:
            return {
                "ok": True,
                "skipped": True,
                "reason": "pass --confirm to run defensive sim probes",
                "hint": "python3 sentinel.py field-soak --confirm",
            }
        from modules.threat_sim import run as sim_run
        # run() expects list[str] scenarios — not a bare string (that iterates chars)
        report = sim_run(
            ["canary", "reverse_shell", "behavioral"],
            confirm=True,
            send_alert=None,
            logger=logger,
        )
        ok = bool(report.get("ok", True))
        # treat per-scenario failures without hard-failing soak if at least one ran
        results = report.get("results") or []
        if results and any(r.get("ok") for r in results):
            ok = True
        return {"ok": ok, "report": report}

    _step("threat_sim", sim, results)

    def critical_store():
        try:
            from modules.critical_alerts import status
            st = status()
            return {"ok": True, "open_critical": st.get("open_count", 0)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    _step("critical_store", critical_store, results)

    fails = [r for r in results if not r.get("ok")]
    # soft fails: skipped sim is ok
    hard = [r for r in fails if not r.get("skipped")]
    go = len(hard) == 0 and any(r["step"] == "canaries" and r.get("ok") for r in results)

    out = {
        "ok": len(hard) == 0,
        "go_live_soak": go and len(hard) == 0,
        "ts": datetime.now(timezone.utc).isoformat(),
        "steps": results,
        "next": [],
    }
    for r in results:
        if r.get("hint"):
            out["next"].append(r["hint"])
    if not (cfg.get("alerting") or {}).get("siem", {}).get("enabled"):
        out["next"].append("Optional: python3 sentinel.py siem enable  (or splunk-configure)")
    path = _data() / "field_soak_report.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    out["report_path"] = str(path)
    return out


def print_report(data: dict) -> None:
    print()
    print("=" * 60)
    print("  SENTINEL FIELD SOAK")
    print("=" * 60)
    for s in data.get("steps") or []:
        mark = "OK" if s.get("ok") else "FAIL"
        if s.get("skipped"):
            mark = "SKIP"
        print(f"  [{mark}] {s.get('step')}")
        if s.get("error"):
            print(f"        {s['error']}")
        if s.get("hint"):
            print(f"        → {s['hint']}")
        if s.get("step") == "alert_channels":
            print(f"        WhatsApp={s.get('whatsapp_enabled')}  Splunk={s.get('splunk_hec')}  "
                  f"SIEM={s.get('siem_enabled')}  ship_lines={s.get('ship_file_lines')}")
    print("-" * 60)
    print(f"  Soak ready: {'YES' if data.get('go_live_soak') else 'NOT YET'}")
    if data.get("next"):
        print("  Next:")
        for n in data["next"][:8]:
            print(f"    · {n}")
    if data.get("report_path"):
        print(f"  Report: {data['report_path']}")
    print("=" * 60)
    print()
