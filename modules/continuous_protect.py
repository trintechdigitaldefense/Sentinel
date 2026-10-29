# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Enhanced continuous protection stack (menu option 1).

Orchestrates: health snapshot → fleet discovery → baselines/canaries →
host start → firewall ARMED (kept running) → dashboard (+ central) → hunt loop.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional


def _home() -> Path:
    return Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))


def _data() -> Path:
    d = _home() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _engine() -> Path:
    return Path(__file__).resolve().parents[1] / "sentinel.py"


def _run_cli(args: list[str], timeout: Optional[int] = None) -> dict:
    cmd = [sys.executable, str(_engine()), *args]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": r.returncode == 0,
            "code": r.returncode,
            "stdout": (r.stdout or "")[-2000:],
            "stderr": (r.stderr or "")[-500:],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": 124, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except Exception:
        return False


def _step_print(c: Any, num: int, total: int, title: str) -> None:
    print(f"\n  {c.CYAN}{c.BOLD}[{num}/{total}]{c.RESET} {title}")


def run_continuous_protection(
    *,
    color: Any = None,
    start_central: bool = True,
    ensure_integrity: bool = True,
    skip_hunt: bool = False,
) -> dict:
    """Run the full continuous-protection bootstrap. Blocks on hunt unless skip_hunt."""
    class _C:
        CYAN = GREEN = YELLOW = RED = BOLD = GRAY = RESET = ""

    c = color or _C()
    total = 8
    result: dict[str, Any] = {
        "ok": True,
        "started_at": datetime.now().isoformat(),
        "steps": {},
        "dashboard_url": None,
        "messages": [],
    }

    def note(msg: str, level: str = "info") -> None:
        result["messages"].append({"level": level, "msg": msg})

    # 1) Health snapshot
    _step_print(c, 1, total, "Health snapshot (doctor)")
    try:
        from modules.doctor import run_doctor
        doc = run_doctor() if callable(run_doctor) else {}
    except Exception:
        try:
            r = _run_cli(["doctor"], timeout=90)
            result["steps"]["doctor"] = r
            print(f"  {c.GREEN}[+]{c.RESET} Doctor finished (code={r.get('code')})")
        except Exception as e:
            result["steps"]["doctor"] = {"ok": False, "error": str(e)}
            print(f"  {c.YELLOW}[!]{c.RESET} Doctor: {e}")
    else:
        # run_doctor may print itself; try CLI for consistent UX
        r = _run_cli(["doctor"], timeout=90)
        result["steps"]["doctor"] = {"ok": r.get("ok"), "code": r.get("code")}
        print(f"  {c.GREEN}[+]{c.RESET} Doctor complete")

    # 2) Fleet discovery
    _step_print(c, 2, total, "Network fleet discovery")
    try:
        from modules.network_fleet import continuous_protect_bootstrap, fleet_status
        boot = continuous_protect_bootstrap(logger=None)
        fleet = boot.get("steps", {}).get("fleet") or fleet_status()
        result["steps"]["fleet"] = {
            "count": fleet.get("count"),
            "method": fleet.get("scan_method"),
            "canary_planted": fleet.get("canary_planted"),
            "pending_agent": fleet.get("canary_pending_agent"),
            "supervised": boot.get("steps", {}).get("supervised_review"),
        }
        print(f"  {c.GREEN}[+]{c.RESET} Hosts found: {fleet.get('count', 0)}  (scan={fleet.get('scan_method')})")
        print(f"  {c.GREEN}[+]{c.RESET} Local canaries: {boot.get('steps', {}).get('local_canaries', {})}")
        pending = (boot.get("steps", {}).get("remote_plan") or {}).get("pending_agent_canaries") or []
        if pending:
            print(f"  {c.YELLOW}[!]{c.RESET} Remote hosts still need agents for canaries: {len(pending)}")
            note(f"pending_agent_canaries={len(pending)}", "warn")
    except Exception as e:
        result["steps"]["fleet"] = {"ok": False, "error": str(e)}
        print(f"  {c.YELLOW}[!]{c.RESET} Fleet: {e}")

    # 3) Integrity baseline if missing
    _step_print(c, 3, total, "File integrity baseline")
    fim = _data() / "integrity_baseline" / "integrity_baseline.json"
    if ensure_integrity and not fim.exists():
        print(f"  {c.GRAY}No FIM baseline — building one...{c.RESET}")
        r = _run_cli(["integrity"], timeout=180)
        result["steps"]["integrity"] = r
        print(f"  {c.GREEN}[+]{c.RESET} Integrity baseline: ok={r.get('ok')}")
    else:
        result["steps"]["integrity"] = {"ok": True, "exists": fim.exists(), "skipped": fim.exists()}
        print(f"  {c.GREEN}[+]{c.RESET} FIM baseline {'present' if fim.exists() else 'skipped'}")

    # 4) Host start (scan + deception + line of defense)
    _step_print(c, 4, total, "Host start (scan + deception + checks)")
    r = _run_cli(["start"], timeout=300)
    result["steps"]["start"] = {"ok": r.get("ok"), "code": r.get("code")}
    print(f"  {c.GREEN}[+]{c.RESET} Start finished (code={r.get('code')})")

    # 5) Firewall — arm plane, keep running, visible on dashboard
    _step_print(c, 5, total, "Host firewall plane — arm & keep running")
    try:
        from modules.firewall import arm_for_continuous, runtime_status
        arm = arm_for_continuous(apply_rules=True)
        rt = runtime_status()
        result["steps"]["firewall"] = {"arm": arm, "runtime": rt}
        mode = arm.get("mode") or rt.get("mode")
        print(f"  {c.GREEN}[+]{c.RESET} Firewall armed={rt.get('armed')}  running={rt.get('running')}  mode={mode}  backend={rt.get('backend')}")
        if arm.get("note"):
            print(f"  {c.GRAY}{arm.get('note')}{c.RESET}")
        if rt.get("error") and rt.get("backend") == "none":
            print(f"  {c.YELLOW}[!]{c.RESET} No nft/iptables here — plane is still ON for dashboard monitoring")
        else:
            print(f"  {c.GREEN}[+]{c.RESET} Operator lockout guard + managed rules applied when backend allows")
    except Exception as e:
        result["steps"]["firewall"] = {"ok": False, "error": str(e)}
        print(f"  {c.YELLOW}[!]{c.RESET} Firewall arm: {e}")
        r = _run_cli(["firewall", "status"], timeout=60)
        result["steps"]["firewall"]["status_cli"] = r.get("code")

    # 6) Dashboard background
    _step_print(c, 6, total, "Client dashboard")
    dash_port = 8792
    try:
        cfg = {}
        cp = _home() / "config.json"
        if cp.exists():
            cfg = json.loads(cp.read_text())
        dash_port = int((cfg.get("dashboard") or {}).get("port") or 8792)
    except Exception:
        pass

    logp = _data() / "dashboard_bg.log"
    if _port_open(dash_port):
        print(f"  {c.GREEN}[+]{c.RESET} Dashboard already listening on :{dash_port}")
        result["steps"]["dashboard"] = {"ok": True, "already_running": True, "port": dash_port}
    else:
        try:
            logp.parent.mkdir(parents=True, exist_ok=True)
            subprocess.Popen(
                [sys.executable, str(_engine()), "dashboard"],
                stdout=open(logp, "a"),
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            time.sleep(1.0)
            result["steps"]["dashboard"] = {"ok": True, "started": True, "port": dash_port}
            print(f"  {c.GREEN}[+]{c.RESET} Dashboard started on port {dash_port}")
        except Exception as e:
            result["steps"]["dashboard"] = {"ok": False, "error": str(e)}
            print(f"  {c.YELLOW}[!]{c.RESET} Dashboard: {e}")

    # Print URL if possible
    try:
        r = _run_cli(["dashboard-url"], timeout=30)
        url_line = ""
        for line in (r.get("stdout") or "").splitlines():
            if "http" in line:
                url_line = line.strip()
                break
        if url_line:
            result["dashboard_url"] = url_line
            print(f"  {c.BOLD}{url_line}{c.RESET}")
        else:
            print(f"  {c.GRAY}Open: python3 sentinel.py dashboard-url{c.RESET}")
    except Exception:
        pass

    # 7) Central listener (optional, non-fatal)
    _step_print(c, 7, total, "Central agent listener (multi-host)")
    central_port = 8743
    try:
        cfg = json.loads((_home() / "config.json").read_text()) if (_home() / "config.json").exists() else {}
        central_port = int((cfg.get("agent") or {}).get("port") or 8743)
    except Exception:
        pass
    if not start_central:
        result["steps"]["central"] = {"skipped": True}
        print(f"  {c.GRAY}Skipped{c.RESET}")
    elif _port_open(central_port):
        result["steps"]["central"] = {"ok": True, "already_running": True, "port": central_port}
        print(f"  {c.GREEN}[+]{c.RESET} Central already on :{central_port}")
    else:
        try:
            clog = _data() / "central_bg.log"
            subprocess.Popen(
                [sys.executable, str(_engine()), "central"],
                stdout=open(clog, "a"),
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            time.sleep(0.8)
            result["steps"]["central"] = {"ok": True, "started": True, "port": central_port}
            print(f"  {c.GREEN}[+]{c.RESET} Central started on :{central_port}")
        except Exception as e:
            result["steps"]["central"] = {"ok": False, "error": str(e)}
            print(f"  {c.YELLOW}[!]{c.RESET} Central: {e}")

    # Heartbeat mark
    try:
        from modules.deadman import emit_heartbeat
        emit_heartbeat(source="continuous-protect")
    except Exception:
        try:
            hb = _data() / "heartbeat.json"
            hb.write_text(json.dumps({"ts": datetime.now().isoformat(), "source": "continuous-protect", "alive": True}))
        except Exception:
            pass

    # Summary before hunt
    print(f"\n  {c.GREEN}{c.BOLD}{'─' * 50}{c.RESET}")
    print(f"  {c.GREEN}{c.BOLD} Continuous protection is armed{c.RESET}")
    print(f"  {c.GRAY}Dashboard + central stay up after you stop the hunt.{c.RESET}")
    if result.get("dashboard_url"):
        print(f"  {c.BOLD}{result['dashboard_url']}{c.RESET}")
    print(f"  {c.GREEN}{c.BOLD}{'─' * 50}{c.RESET}\n")

    # 8) Hunt loop (blocking)
    _step_print(c, 8, total, "Continuous hunt loop — Ctrl+C to return to menu")
    result["steps"]["hunt"] = {"started": True}
    if skip_hunt:
        result["steps"]["hunt"]["skipped"] = True
        result["finished_at"] = datetime.now().isoformat()
        return result

    # Interactive hunt — inherit stdout
    try:
        rc = subprocess.call([sys.executable, str(_engine()), "hunt"])
        result["steps"]["hunt"]["code"] = rc
    except KeyboardInterrupt:
        result["steps"]["hunt"]["stopped"] = True
        print(f"\n  {c.YELLOW}Hunt stopped — dashboard/central may still be running.{c.RESET}")
    result["finished_at"] = datetime.now().isoformat()

    # Final tip
    print(f"\n  {c.CYAN}Still running in background (if started):{c.RESET}")
    print(f"  {c.GRAY}• Dashboard  ·  python3 sentinel.py dashboard-url{c.RESET}")
    print(f"  {c.GRAY}• Central    ·  curl -s http://127.0.0.1:{central_port}/health{c.RESET}")
    print(f"  {c.GRAY}• Firewall   ·  visible on dashboard Defense / status hero{c.RESET}")
    print(f"  {c.GRAY}• Resume     ·  menu option 1 or: python3 sentinel.py hunt{c.RESET}\n")
    return result
