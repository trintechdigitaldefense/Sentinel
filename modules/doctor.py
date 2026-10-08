#!/usr/bin/env python3
"""SENTINEL doctor — single green/red readiness check for client installs."""
from __future__ import annotations
import json
import os
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

VERSION = "2.6.1"

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
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}

def _ok(name: str, detail: str = "") -> dict:
    return {"name": name, "status": "OK", "detail": detail}

def _warn(name: str, detail: str = "") -> dict:
    return {"name": name, "status": "WARN", "detail": detail}

def _fail(name: str, detail: str = "") -> dict:
    return {"name": name, "status": "FAIL", "detail": detail}

def _run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)

def check_engine() -> dict:
    candidates = [
        Path.cwd() / "sentinel.py",
        Path(__file__).resolve().parent.parent / "sentinel.py",
    ]
    for p in candidates:
        if p.exists() and p.stat().st_size > 20000:
            return _ok("engine", f"{p} ({p.stat().st_size} bytes)")
    for p in candidates:
        if p.exists():
            return _fail("engine", f"{p} too small ({p.stat().st_size} B) — run: python3 setup.py")
    return _fail("engine", "sentinel.py missing — clone repo and run python3 setup.py")

def check_config() -> dict:
    p = _cfg_path()
    if not p.exists():
        return _warn("config", f"missing {p} — will create on first run")
    c = _load_cfg()
    if not c:
        return _fail("config", f"unreadable or empty: {p}")
    return _ok("config", str(p))

def check_subnet() -> dict:
    c = _load_cfg()
    nets = (c.get("network") or {}).get("scan_subnets") or []
    if not nets:
        return _warn("subnet", "no scan_subnets set — run: python3 sentinel.py autosubnet")
    bad = [s for s in nets if str(s).endswith(("/8", "/12", "/11", "/10", "/9"))]
    if bad:
        return _fail("subnet", f"too wide: {bad} — restrict to office /24")
    return _ok("subnet", ", ".join(str(x) for x in nets))

def check_permissions() -> dict:
    home = _home()
    data = _data()
    try:
        home.mkdir(parents=True, exist_ok=True)
        data.mkdir(parents=True, exist_ok=True)
        mode_h = oct(home.stat().st_mode)[-3:]
        mode_d = oct(data.stat().st_mode)[-3:]
        detail = f"{home}={mode_h} data={mode_d}"
        if mode_h in ("700", "750") or mode_d in ("700", "750"):
            return _ok("permissions", detail)
        return _warn("permissions", detail + " (prefer 700)")
    except Exception as e:
        return _fail("permissions", str(e))

def check_baseline() -> dict:
    candidates = [
        _data() / "integrity_baseline" / "integrity_baseline.json",
        _data() / "integrity_baseline.json",
        _home() / "data" / "integrity_baseline" / "integrity_baseline.json",
    ]
    for p in candidates:
        if p.exists() and p.stat().st_size > 10:
            return _ok("fim_baseline", str(p))
    return _warn("fim_baseline", "none — run menu 5 or: python3 sentinel.py integrity")

def check_canaries() -> dict:
    decoy = _data() / "deception_artifacts"
    if not decoy.exists():
        return _warn("canaries", "not deployed — run: python3 sentinel.py deception")
    files = list(decoy.rglob("*"))
    nfiles = sum(1 for f in files if f.is_file())
    if nfiles >= 3:
        return _ok("canaries", f"artifacts dir present ({nfiles} files)")
    return _warn("canaries", "dir exists but sparse — redeploy deception")

def check_heartbeat() -> dict:
    p = _data() / "heartbeat.json"
    if not p.exists():
        return _warn("heartbeat", "no heartbeat yet — start hunt or service-install")
    try:
        d = json.loads(p.read_text())
        ts = d.get("ts") or d.get("timestamp") or d.get("time")
        age = None
        if ts:
            try:
                age = int((datetime.now() - datetime.fromisoformat(str(ts).replace("Z", ""))).total_seconds())
            except Exception:
                age = None
        if age is not None and age < 600:
            return _ok("heartbeat", f"fresh ({age}s ago) source={d.get('source', '?')}")
        if age is not None:
            return _warn("heartbeat", f"stale ({age}s ago) — is hunt/service running?")
        return _warn("heartbeat", f"present but no parseable ts: {list(d.keys())[:6]}")
    except Exception as e:
        return _fail("heartbeat", str(e))

def check_service() -> dict:
    code, out = _run(["systemctl", "is-active", "sentinel.service"])
    if code == 0 and "active" in out:
        return _ok("service", "systemd sentinel.service active")
    code2, out2 = _run(["systemctl", "--user", "is-active", "sentinel.service"])
    if code2 == 0 and "active" in out2:
        return _ok("service", "user systemd sentinel.service active")
    return _warn("service", "not active — run: python3 sentinel.py service-install")

def check_modules() -> dict:
    root = Path(__file__).resolve().parent
    needed = ["phase5.py", "phase6.py", "phase7.py", "doctor.py"]
    missing = [n for n in needed if not (root / n).exists()]
    if missing:
        return _fail("modules", f"missing {missing} — git pull origin main")
    return _ok("modules", "phase5–7 + doctor present")

def check_commands_wired() -> dict:
    eng = Path.cwd() / "sentinel.py"
    if not eng.exists():
        eng = Path(__file__).resolve().parent.parent / "sentinel.py"
    if not eng.exists() or eng.stat().st_size < 20000:
        return _warn("commands", "engine not assembled — setup.py first")
    src = eng.read_text(errors="ignore")
    want = ["doctor", "service-install", "hygiene", "quiet"]
    missing = [w for w in want if w not in src]
    if missing:
        return _warn("commands", f"not wired: {missing} — re-run setup.py")
    return _ok("commands", "doctor, service, hygiene, quiet present in engine")

def check_whatsapp() -> dict:
    c = _load_cfg()
    wa = (c.get("alerting") or {}).get("whatsapp") or {}
    if not wa.get("enabled"):
        return _ok("whatsapp", "disabled (optional)")
    if not wa.get("apikey"):
        return _warn("whatsapp", "enabled but no apikey")
    phone = wa.get("phone") or wa.get("number") or ""
    return _ok("whatsapp", f"enabled phone={phone or '?'}")

def check_host() -> dict:
    try:
        host = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "unknown"
        finally:
            s.close()
        return _ok("host", f"{host} ip={ip}")
    except Exception as e:
        return _warn("host", str(e))

def run_doctor(verbose: bool = True) -> dict:
    checks = [
        check_host(),
        check_engine(),
        check_modules(),
        check_commands_wired(),
        check_config(),
        check_subnet(),
        check_permissions(),
        check_baseline(),
        check_canaries(),
        check_heartbeat(),
        check_service(),
        check_whatsapp(),
    ]
    ok = sum(1 for c in checks if c["status"] == "OK")
    warn = sum(1 for c in checks if c["status"] == "WARN")
    fail = sum(1 for c in checks if c["status"] == "FAIL")
    ready = fail == 0 and ok >= 6
    result = {
        "ok": fail == 0,
        "client_ready": ready and warn <= 4,
        "version": VERSION,
        "summary": {"ok": ok, "warn": warn, "fail": fail},
        "checks": checks,
        "next": [],
    }
    for c in checks:
        if c["status"] == "FAIL":
            if c["name"] == "engine":
                result["next"].append("python3 setup.py")
            elif c["name"] == "subnet":
                result["next"].append("python3 sentinel.py autosubnet")
            elif c["name"] == "modules":
                result["next"].append("git pull origin main")
        elif c["status"] == "WARN":
            if c["name"] == "fim_baseline":
                result["next"].append("python3 sentinel.py integrity")
            elif c["name"] == "canaries":
                result["next"].append("python3 sentinel.py deception")
            elif c["name"] == "service":
                result["next"].append("python3 sentinel.py service-install")
            elif c["name"] == "heartbeat":
                result["next"].append("python3 sentinel.py hunt   # or service-install")
    seen = set()
    nxt = []
    for x in result["next"]:
        if x not in seen:
            seen.add(x)
            nxt.append(x)
    result["next"] = nxt

    if verbose:
        print()
        print("=" * 56)
        print("  SENTINEL DOCTOR")
        print("=" * 56)
        for c in checks:
            mark = {"OK": "+", "WARN": "!", "FAIL": "X"}.get(c["status"], "?")
            print(f"  [{mark}] {c['status']:4}  {c['name']:12}  {c['detail']}")
        print("-" * 56)
        print(f"  Summary: {ok} OK · {warn} WARN · {fail} FAIL")
        if result["client_ready"]:
            print("  Verdict: CLIENT-READY (fix remaining WARNs as needed)")
        elif result["ok"]:
            print("  Verdict: INSTALL OK — complete WARNs before production")
        else:
            print("  Verdict: NOT READY — fix FAIL items first")
        if result["next"]:
            print("  Next:")
            for n in result["next"]:
                print(f"    → {n}")
        print("=" * 56)
        print()
    return result

if __name__ == "__main__":
    run_doctor(True)
