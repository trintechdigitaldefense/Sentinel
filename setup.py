#!/usr/bin/env python3
"""SENTINEL single install — TrinTech Digital Defense v2.9.7

One path:
  assemble (if needed) → stabilize (all wires + fixes) → defaults → doctor
"""
from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
VERSION = "2.9.7"


def run(cmd: list) -> int:
    print(f"\n[*] {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


def engine_looks_complete() -> bool:
    if not ENGINE.exists() or ENGINE.stat().st_size < 50000:
        return False
    try:
        py_compile.compile(str(ENGINE), doraise=True)
    except Exception:
        return False
    src = ENGINE.read_text(errors="ignore")
    need = ["doctor", "hunt", "dashboard", "while True"]
    return all(n in src for n in need)


def step_assemble() -> None:
    if engine_looks_complete() and "--force-assemble" not in sys.argv:
        print(f"[=] Engine already complete ({ENGINE.stat().st_size} bytes) — skip assemble")
        print("    (pass --force-assemble to rebuild from chunks)")
        return
    asm = ROOT / "assemble_engine.py"
    if not asm.exists():
        if ENGINE.exists() and ENGINE.stat().st_size > 50000:
            print("[=] Using existing sentinel.py (no assemble_engine.py)")
            return
        print("[!] Missing assemble_engine.py and no usable engine")
        sys.exit(1)
    if run([sys.executable, str(asm)]) != 0:
        print("[!] assemble failed")
        sys.exit(1)


def step_stabilize() -> None:
    stab = ROOT / "stabilize.py"
    if not stab.exists():
        print("[!] stabilize.py missing — falling back to legacy wire loop")
        for script in (
            "wire_phase4.py", "fix_ui.py", "wire_phase5.py", "wire_phase6.py",
            "wire_phase7.py", "wire_doctor.py", "wire_drift_deadman.py",
            "wire_revenue_tier2.py", "wire_portal_harden.py", "wire_bonus.py",
            "wire_dashboard.py", "wire_cli_safe.py", "rebuild_hooks.py",
            "fix_self_integrity.py", "fix_process_scan.py",
        ):
            p = ROOT / script
            if p.exists():
                run([sys.executable, str(p)])
        return
    if run([sys.executable, str(stab)]) != 0:
        print("[!] stabilize reported failure — check output above")


def step_clear_integrity() -> None:
    for p in {
        Path.home() / ".sentinel/data/self_integrity.json",
        Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "data/self_integrity.json",
    }:
        if p.exists():
            try:
                p.unlink()
                print(f"[+] Cleared {p}")
            except Exception as e:
                print(f"[=] could not clear {p}: {e}")


def step_harden_defaults() -> None:
    cfg_path = Path.home() / ".sentinel/config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    (Path.home() / ".sentinel/data").mkdir(parents=True, exist_ok=True)
    c = {}
    if cfg_path.exists():
        try:
            c = json.loads(cfg_path.read_text())
        except Exception:
            c = {}
    net = c.setdefault("network", {})
    net.setdefault("scan_subnets", ["192.168.1.0/24"])
    agent = c.setdefault("agent", {})
    agent.setdefault("shared_token", "")
    agent.setdefault("central_url", "")
    al = c.setdefault("alerting", {})
    wa = al.setdefault("whatsapp", {})
    wa.setdefault("enabled", False)
    wa.setdefault("phone", "18683620679")
    wa.setdefault("apikey", "")
    p5 = c.setdefault("phase5", {})
    hy = p5.setdefault("hygiene", {})
    hy.setdefault("enabled", True)
    hy.setdefault("window_sec", 900)
    hy.setdefault("max_per_key", 1)
    dm = c.setdefault("deadman", {})
    dm.setdefault("enabled", True)
    dm.setdefault("interval_sec", 300)
    dm.setdefault("timeout_sec", 600)
    portal = c.setdefault("portal", {})
    portal.setdefault("port", 8791)
    portal.setdefault("enabled", True)
    portal.setdefault("client_name", "Client")
    dash = c.setdefault("dashboard", {})
    dash.setdefault("port", 8792)
    dash.setdefault("bind", "127.0.0.1")
    dash.setdefault("enabled", True)
    dash.setdefault("allow_control", True)
    dash.setdefault("client_name", "Client")
    c.setdefault("usb_watch", False)
    c.setdefault("external", {"domain": "", "host": ""})
    c["version"] = VERSION
    cfg_path.write_text(json.dumps(c, indent=2))
    try:
        os.chmod(cfg_path, 0o600)
    except Exception:
        pass
    print(f"[+] Defaults written → {cfg_path}")


def step_doctor() -> None:
    doc = ROOT / "modules" / "doctor.py"
    if not doc.exists():
        return
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [sys.executable, "-c", "from modules.doctor import run_doctor; run_doctor(True)"],
        cwd=str(ROOT),
        env=env,
    )


def step_verify() -> None:
    print("\n" + "=" * 56)
    print(f"  SENTINEL SETUP COMPLETE  (v{VERSION})")
    print("=" * 56)
    try:
        py_compile.compile(str(ENGINE), doraise=True)
        print(f"  [+] Engine compiles ({ENGINE.stat().st_size} bytes)")
    except Exception as e:
        print(f"  [!] Engine compile problem: {e}")
    print("""
  Daily use:
    python3 setup.py                 # this installer
    python3 sentinel.py doctor
    python3 sentinel.py deception
    python3 sentinel.py hunt         # or service-install
    python3 sentinel.py dash         # login dashboard

  Force rebuild from chunks:
    python3 setup.py --force-assemble
""")


def main() -> None:
    print("SENTINEL single install — TrinTech Digital Defense")
    print(f"Repo: {ROOT}")
    step_assemble()
    step_stabilize()
    step_clear_integrity()
    step_harden_defaults()
    step_doctor()
    step_verify()


if __name__ == "__main__":
    main()
