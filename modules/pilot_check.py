# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Pilot validation workflow for client-site go-live.

Phases:
  1. Preflight   — doctor + detection modules
  2. Baselines   — FIM / SUID / persistence (create if missing)
  3. Deception   — deploy canaries when possible
  4. Detection   — process scan, behavioral shell, firewall dry-run
  5. Service     — service status / install guidance
  6. Report      — write pilot_report.json + go/no-go checklist

Usage:
  python3 sentinel.py pilot
  python3 sentinel.py pilot --fix     # also try to clear common gaps
  python3 sentinel.py pilot --json      # machine-readable only at end
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _step(out: dict, name: str, ok: bool, **extra) -> None:
    rec = {"step": name, "ok": ok, **extra}
    out.setdefault("steps", []).append(rec)
    if not ok:
        out["ok"] = False


def _print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _print_step(name: str, ok: bool, detail: str = "") -> None:
    mark = "+" if ok else "X"
    line = f"  [{mark}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)


def run_pilot(
    logger=None,
    fix: bool = False,
    quiet_json: bool = False,
    deploy_deception_fn: Optional[Callable] = None,
    config: Optional[dict] = None,
) -> dict:
    """Full pilot validation. Returns structured result + writes pilot_report.json."""
    out: dict[str, Any] = {
        "ok": True,
        "ts": _now(),
        "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "phases": {},
        "steps": [],
        "checklist": [],
        "next": [],
    }

    if not quiet_json:
        _print_header("SENTINEL PILOT VALIDATION WORKFLOW")
        print(f"  Host: {out['host']}  Time: {out['ts']}")
        if fix:
            print("  Mode: --fix (will create missing baselines / attempt remediation)")
        print()

    # ── Phase 1: Preflight ──────────────────────────────────────────
    if not quiet_json:
        print("── Phase 1: Preflight")
    phase1: dict[str, Any] = {"ok": True}

    try:
        from modules.doctor import run_doctor
        d = run_doctor(verbose=not quiet_json)
        phase1["doctor"] = {
            "ok": d.get("ok"),
            "client_ready": d.get("client_ready"),
            "summary": d.get("summary"),
            "next": d.get("next"),
        }
        _step(out, "doctor", bool(d.get("ok")), summary=d.get("summary"))
        if not quiet_json:
            _print_step("doctor", bool(d.get("ok")), json.dumps(d.get("summary")))
        if not d.get("ok"):
            phase1["ok"] = False
        for n in d.get("next") or []:
            if n not in out["next"]:
                out["next"].append(n)
    except Exception as e:
        phase1["ok"] = False
        _step(out, "doctor", False, error=str(e))
        if not quiet_json:
            _print_step("doctor", False, str(e))

    try:
        root = Path(__file__).resolve().parent
        need = [
            "behavioral_shell.py", "persistence_hunt.py", "fim_suid.py",
            "fim_realtime.py", "firewall.py", "alerting.py", "doctor.py",
        ]
        missing = [n for n in need if not (root / n).exists()]
        ok = not missing
        _step(out, "detection_modules", ok, missing=missing or None)
        if not quiet_json:
            _print_step("detection_modules", ok, "all present" if ok else f"missing {missing}")
        if not ok:
            phase1["ok"] = False
            out["ok"] = False
    except Exception as e:
        _step(out, "detection_modules", False, error=str(e))
        phase1["ok"] = False

    out["phases"]["preflight"] = phase1

    # ── Phase 2: Baselines ──────────────────────────────────────────
    if not quiet_json:
        print("\n── Phase 2: Baselines")
    phase2: dict[str, Any] = {"ok": True}

    # Persistence
    try:
        from modules.persistence_hunt import baseline_path, create_baseline, check, status as per_status
        if not baseline_path().exists() or fix:
            r = create_baseline()
            _step(out, "persistence_baseline", True, created=True, count=r.get("count"))
            if not quiet_json:
                _print_step("persistence_baseline", True, f"created {r.get('count')} entries")
        else:
            st = per_status()
            c = check()
            _step(out, "persistence_baseline", True, count=st.get("baseline_count"), events=c.get("count", 0))
            if not quiet_json:
                _print_step("persistence_baseline", True, f"{st.get('baseline_count')} entries, {c.get('count', 0)} drift events")
    except Exception as e:
        phase2["ok"] = False
        _step(out, "persistence_baseline", False, error=str(e))
        if not quiet_json:
            _print_step("persistence_baseline", False, str(e))
        out["next"].append("python3 sentinel.py persistence-baseline")

    # SUID
    try:
        from modules.fim_suid import build_baseline, status as su_status, check as su_check
        st = su_status()
        if not st.get("baseline_exists") or fix:
            r = build_baseline()
            _step(out, "suid_baseline", True, created=True, count=r.get("count"))
            if not quiet_json:
                _print_step("suid_baseline", True, f"created {r.get('count')} binaries")
        else:
            ch = su_check()
            _step(out, "suid_baseline", True, count=st.get("baseline_count"), changes=len(ch))
            if not quiet_json:
                _print_step("suid_baseline", True, f"{st.get('baseline_count')} binaries, {len(ch)} changes")
    except Exception as e:
        phase2["ok"] = False
        _step(out, "suid_baseline", False, error=str(e))
        if not quiet_json:
            _print_step("suid_baseline", False, str(e))
        out["next"].append("python3 sentinel.py integrity")

    # FIM baseline presence
    try:
        fim = _data() / "integrity_baseline" / "integrity_baseline.json"
        if fim.exists():
            n = len(json.loads(fim.read_text()))
            _step(out, "fim_baseline", True, files=n)
            if not quiet_json:
                _print_step("fim_baseline", True, f"{n} files tracked")
        else:
            _step(out, "fim_baseline", False, detail="missing")
            phase2["ok"] = False
            if not quiet_json:
                _print_step("fim_baseline", False, "run: python3 sentinel.py integrity")
            out["next"].append("python3 sentinel.py integrity")
            if fix and logger is not None:
                # Cannot call fim_build without full sentinel context reliably
                pass
    except Exception as e:
        _step(out, "fim_baseline", False, error=str(e))
        phase2["ok"] = False

    out["phases"]["baselines"] = phase2

    # ── Phase 3: Deception ──────────────────────────────────────────
    if not quiet_json:
        print("\n── Phase 3: Deception / canaries")
    phase3: dict[str, Any] = {"ok": True}
    decoy = _data() / "deception_artifacts"
    tracker = decoy / "config.json"
    canary_ok = False
    try:
        alive = 0
        tracked = 0
        if tracker.exists():
            data = json.loads(tracker.read_text())
            if isinstance(data, dict):
                tracked = len(data)
                for path in data.keys():
                    try:
                        if Path(path).exists():
                            alive += 1
                    except Exception:
                        pass
        nfiles = sum(1 for f in decoy.rglob("*") if f.is_file()) if decoy.exists() else 0
        canary_ok = (tracked >= 6 and alive >= 3) or nfiles >= 6
        if canary_ok:
            _step(out, "canaries", True, tracked=tracked, alive=alive, files=nfiles)
            if not quiet_json:
                _print_step("canaries", True, f"tracked={tracked} alive={alive} files={nfiles}")
        else:
            if fix and deploy_deception_fn and config is not None and logger is not None:
                try:
                    deploy_deception_fn(config, logger)
                    _step(out, "canaries", True, deployed=True)
                    if not quiet_json:
                        _print_step("canaries", True, "deployed via --fix")
                    canary_ok = True
                except Exception as e:
                    _step(out, "canaries", False, error=str(e))
                    phase3["ok"] = False
                    if not quiet_json:
                        _print_step("canaries", False, str(e))
            else:
                _step(out, "canaries", False, tracked=tracked, alive=alive, files=nfiles)
                phase3["ok"] = False
                if not quiet_json:
                    _print_step("canaries", False, "run: python3 sentinel.py deception")
                out["next"].append("python3 sentinel.py deception")
    except Exception as e:
        _step(out, "canaries", False, error=str(e))
        phase3["ok"] = False
    out["phases"]["deception"] = phase3

    # ── Phase 4: Detection probes ───────────────────────────────────
    if not quiet_json:
        print("\n── Phase 4: Detection probes")
    phase4: dict[str, Any] = {"ok": True}

    try:
        from modules.behavioral_shell import scan
        hits = scan()
        _step(out, "behavioral_scan", True, hits=len(hits))
        if not quiet_json:
            _print_step("behavioral_scan", True, f"{len(hits)} hits (0 expected on clean host)")
    except Exception as e:
        phase4["ok"] = False
        _step(out, "behavioral_scan", False, error=str(e))
        if not quiet_json:
            _print_step("behavioral_scan", False, str(e))

    try:
        from modules.firewall import block_ip, detect_operator_ips, status as fw_status
        st = fw_status()
        r = block_ip("203.0.113.50", confirm=False)
        # lockout: refuse localhost
        refused = block_ip("127.0.0.1", confirm=True)
        ops = detect_operator_ips()
        ok = bool(r.get("dry_run")) and refused.get("ok") is False and st.get("lockout_guard")
        _step(
            out, "firewall_probe", ok,
            backend=st.get("backend"),
            lockout_guard=st.get("lockout_guard"),
            operator_ips=ops,
            dry_run=r.get("would"),
        )
        if not quiet_json:
            _print_step(
                "firewall_probe", ok,
                f"backend={st.get('backend')} lockout={st.get('lockout_guard')} ops={ops}",
            )
        if not ok:
            phase4["ok"] = False
    except Exception as e:
        phase4["ok"] = False
        _step(out, "firewall_probe", False, error=str(e))
        if not quiet_json:
            _print_step("firewall_probe", False, str(e))

    # Safe canary content probe (read-only): list one decoy if present
    try:
        sample = None
        if decoy.exists():
            for f in decoy.rglob("*"):
                if f.is_file() and f.name != "config.json":
                    sample = str(f)
                    break
        _step(out, "canary_sample", True, sample=sample)
        if not quiet_json:
            _print_step("canary_sample", True, sample or "none yet")
    except Exception as e:
        _step(out, "canary_sample", False, error=str(e))

    out["phases"]["detection"] = phase4

    # ── Phase 5: Service / continuous ───────────────────────────────
    if not quiet_json:
        print("\n── Phase 5: Continuous protection")
    phase5: dict[str, Any] = {"ok": True}
    try:
        from modules.phase5 import service_status
        st = service_status()
        running = st.get("status") in ("running", "active") or st.get("ok") and "running" in str(st.get("status", ""))
        # softer: accept method present
        detail = json.dumps(st)[:200]
        if running or st.get("status") == "running":
            _step(out, "service", True, **{k: st.get(k) for k in ("method", "status", "pid") if k in st})
            if not quiet_json:
                _print_step("service", True, detail)
        else:
            _step(out, "service", False, status=st)
            phase5["ok"] = False
            if not quiet_json:
                _print_step("service", False, "not active — python3 sentinel.py service-install")
            out["next"].append("python3 sentinel.py service-install")
    except Exception as e:
        # heartbeat as fallback signal
        hb = _data() / "heartbeat.json"
        if hb.exists():
            _step(out, "service", True, via="heartbeat.json")
            if not quiet_json:
                _print_step("service", True, "heartbeat present")
        else:
            _step(out, "service", False, error=str(e))
            phase5["ok"] = False
            if not quiet_json:
                _print_step("service", False, "no service / heartbeat")
            out["next"].append("python3 sentinel.py service-install")
    out["phases"]["service"] = phase5

    # ── Checklist / go-no-go ────────────────────────────────────────
    checks_map = {s["step"]: s for s in out["steps"]}
    checklist = [
        ("Doctor has zero FAILs", bool(checks_map.get("doctor", {}).get("ok"))),
        ("Persistence baseline exists", bool(checks_map.get("persistence_baseline", {}).get("ok"))),
        ("SUID baseline exists", bool(checks_map.get("suid_baseline", {}).get("ok"))),
        ("FIM baseline exists", bool(checks_map.get("fim_baseline", {}).get("ok"))),
        ("Canaries deployed", bool(checks_map.get("canaries", {}).get("ok"))),
        ("Behavioral scan runs", bool(checks_map.get("behavioral_scan", {}).get("ok"))),
        ("Firewall dry-run + lockout guard", bool(checks_map.get("firewall_probe", {}).get("ok"))),
        ("Continuous service or hunt", bool(checks_map.get("service", {}).get("ok"))),
    ]
    out["checklist"] = [{"item": i, "pass": p} for i, p in checklist]
    passed = sum(1 for _, p in checklist if p)
    total = len(checklist)
    # Soft go: doctor + baselines + detection probes (service may be manual)
    critical_ok = all(
        checks_map.get(s, {}).get("ok")
        for s in ("doctor", "persistence_baseline", "suid_baseline", "behavioral_scan", "firewall_probe")
    )
    out["go_live"] = critical_ok and bool(checks_map.get("fim_baseline", {}).get("ok")) and bool(
        checks_map.get("canaries", {}).get("ok")
    )
    out["ok"] = critical_ok  # pilot workflow itself succeeded on critical path
    if not checks_map.get("fim_baseline", {}).get("ok") or not checks_map.get("canaries", {}).get("ok"):
        out["ok"] = False

    # Dedupe next
    seen = set()
    nxt = []
    for x in out["next"]:
        if x not in seen:
            seen.add(x)
            nxt.append(x)
    out["next"] = nxt

    # Write report
    report_path = _data() / "pilot_report.json"
    try:
        report_path.write_text(json.dumps(out, indent=2, default=str))
        out["report"] = str(report_path)
    except Exception as e:
        out["report_error"] = str(e)

    if not quiet_json:
        print("\n── Go / No-Go checklist")
        for item in out["checklist"]:
            mark = "PASS" if item["pass"] else "FAIL"
            print(f"  [{mark}] {item['item']}")
        print("-" * 60)
        print(f"  Score: {passed}/{total}")
        if out.get("go_live"):
            print("  Verdict: GO-LIVE READY — continuous service recommended")
        elif critical_ok:
            print("  Verdict: ALMOST — finish FIM/canaries/service items below")
        else:
            print("  Verdict: NO-GO — fix failed critical steps")
        if out["next"]:
            print("  Next actions:")
            for n in out["next"]:
                print(f"    → {n}")
        if out.get("report"):
            print(f"  Report: {out['report']}")
        print("=" * 60)
        print()

    return out
