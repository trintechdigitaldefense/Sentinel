
from __future__ import annotations
import logging

def _check_dashboard_password(results):
    try:
        from modules.rbac import must_change_password
        from pathlib import Path
        import json, os
        cfg_path = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        dash = cfg.get("dashboard") or {}
        if "password" in dash and must_change_password(cfg):
            results.append({"name": "dashboard_password", "ok": False, "level": "FAIL",
                            "detail": "default/empty dashboard password — change dashboard.password"})
        else:
            results.append({"name": "dashboard_password", "ok": True, "level": "OK",
                            "detail": "password ok or unused"})
    except Exception as e:
        results.append({"name": "dashboard_password", "ok": True, "level": "WARN", "detail": str(e)})


def _check_config_perms(results):
    try:
        from pathlib import Path
        import os
        cfg_path = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "config.json"
        if not cfg_path.exists():
            results.append({"name": "config_perms", "ok": True, "level": "OK", "detail": "no config yet"})
            return
        mode = cfg_path.stat().st_mode & 0o777
        if mode & 0o077:
            try:
                os.chmod(cfg_path, 0o600)
                results.append({"name": "config_perms", "ok": True, "level": "WARN",
                                "detail": "was %s, tightened to 0600" % oct(mode)})
            except Exception as e:
                results.append({"name": "config_perms", "ok": False, "level": "FAIL",
                                "detail": "mode %s: %s" % (oct(mode), e)})
        else:
            results.append({"name": "config_perms", "ok": True, "level": "OK", "detail": oct(mode)})
    except Exception as e:
        results.append({"name": "config_perms", "ok": True, "level": "WARN", "detail": str(e)})

#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL doctor — single green/red readiness check for client installs."""
import json
import os
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

VERSION = "2.7.0"

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
    """Validate scan_subnets; auto-sanitize overly wide ranges when possible."""
    try:
        from modules.subnet_guard import is_too_wide, sanitize_config_subnets
    except Exception:
        is_too_wide = None
        sanitize_config_subnets = None

    c = _load_cfg()
    nets = (c.get("network") or {}).get("scan_subnets") or []
    if not nets:
        return _warn("subnet", "no scan_subnets set — run: python3 sentinel.py autosubnet")

    if is_too_wide:
        bad = [s for s in nets if is_too_wide(str(s))]
    else:
        bad = [s for s in nets if str(s).endswith(("/8", "/12", "/11", "/10", "/9", "/0"))]

    if bad and sanitize_config_subnets:
        fixed = sanitize_config_subnets()
        if fixed.get("changed"):
            nets = fixed.get("subnets") or []
            return _warn(
                "subnet",
                f"auto-restricted from {bad} → {nets} (was too wide)",
            )
        return _fail("subnet", f"too wide: {bad} — run: python3 sentinel.py sanitize-subnets")
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
    """Count real canaries from tracker (config.json), not just dir file count."""
    from pathlib import Path as _P
    decoy = _data() / "deception_artifacts"
    tracker_path = decoy / "config.json"
    if not decoy.exists() and not tracker_path.exists():
        return _warn("canaries", "not deployed — run: python3 sentinel.py deception")
    tracked = 0
    alive = 0
    if tracker_path.exists():
        try:
            data = json.loads(tracker_path.read_text())
            if isinstance(data, dict):
                tracked = len(data)
                for path in data.keys():
                    try:
                        if _P(path).exists():
                            alive += 1
                    except Exception as e:
                        logging.getLogger('sentinel').debug('%s: %s', __name__, e)

        except Exception as e:
            logging.getLogger('sentinel').debug('%s: %s', __name__, e)

    if tracked >= 6 and alive >= 3:
        return _ok("canaries", f"{alive}/{tracked} canaries alive on disk")
    if tracked >= 1:
        return _warn("canaries", f"tracker has {tracked} entries, {alive} alive — redeploy deception")
    nfiles = sum(1 for f in decoy.rglob("*") if f.is_file()) if decoy.exists() else 0
    if nfiles >= 3:
        return _ok("canaries", f"artifacts dir present ({nfiles} files)")
    return _warn("canaries", "not deployed — run: python3 sentinel.py deception")

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
    """Always-on hunt: systemd or background pid (Termux)."""
    try:
        from modules.always_on import status as always_status
        st = always_status()
        status = str(st.get("status") or "").lower()
        if st.get("ok") and status in ("active", "running"):
            return _ok("service", st.get("summary") or f"{st.get('method')}:{st.get('status')}")
        if status in ("running", "active"):
            return _ok("service", st.get("summary") or status)
    except Exception as e:
        logging.getLogger('sentinel').debug('%s: %s', __name__, e)


    for unit in ("sentinel-hunt.service", "sentinel.service", "sentinel-central.service"):
        code, out = _run(["systemctl", "is-active", unit])
        if code == 0 and "active" in (out or ""):
            return _ok("service", f"systemd {unit} active")
        code2, out2 = _run(["systemctl", "--user", "is-active", unit])
        if code2 == 0 and "active" in (out2 or ""):
            return _ok("service", f"user systemd {unit} active")

    import os
    pidfile = _data() / "hunt.pid"
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 0)
            return _ok("service", f"background hunt running (pid {pid})")
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            try:
                pidfile.unlink(missing_ok=True)
            except Exception as e:
                logging.getLogger('sentinel').debug('%s: %s', __name__, e)

            return _warn("service", "stale hunt.pid removed — re-run: python3 sentinel.py service-install")
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


def check_persistence() -> dict:
    p = _data() / "persistence_baseline.json"
    if not p.exists():
        return _warn("persistence", "no baseline — run: python3 sentinel.py persistence-baseline")
    try:
        d = json.loads(p.read_text())
        n = int(d.get("count") or len(d.get("entries") or {}))
        return _ok("persistence", f"baseline {n} entries")
    except Exception as e:
        return _fail("persistence", str(e))


def check_suid() -> dict:
    p = _data() / "suid_baseline.json"
    if not p.exists():
        return _warn("suid", "no SUID baseline — run: python3 sentinel.py integrity")
    try:
        d = json.loads(p.read_text())
        n = int(d.get("count") or len(d.get("binaries") or {}))
        return _ok("suid", f"baseline {n} setuid/setgid binaries")
    except Exception as e:
        return _fail("suid", str(e))


def check_detection_modules() -> dict:
    root = Path(__file__).resolve().parent
    need = [
        "behavioral_shell.py", "persistence_hunt.py", "fim_suid.py",
        "fim_realtime.py", "firewall.py", "alerting.py", "brute_force.py", "visibility.py",
    ]
    missing = [n for n in need if not (root / n).exists()]
    if missing:
        return _fail("detection_mods", f"missing: {', '.join(missing)}")
    return _ok("detection_mods", f"{len(need)} core detection modules present")


def check_firewall_plane() -> dict:
    try:
        from modules.firewall import status as fw_status
        st = fw_status()
        if not st.get("lockout_guard"):
            return _warn("firewall", "lockout_guard missing — update Sentinel")
        backend = st.get("backend") or "none"
        if backend == "none":
            return _warn("firewall", "no nft/iptables (OK on Termux; need root host for blocks)")
        return _ok("firewall", f"backend={backend} lockout_guard=on ipv6={st.get('ipv6')}")
    except Exception as e:
        return _warn("firewall", f"unavailable: {e}")


def check_offline_queue() -> dict:
    p = _data() / "offline_queue.jsonl"
    if not p.exists():
        return _ok("offline_queue", "empty (no backlog)")
    try:
        n = sum(1 for ln in p.read_text().splitlines() if ln.strip())
        if n > 100:
            return _warn("offline_queue", f"{n} queued alerts — run: python3 sentinel.py offline flush")
        if n > 0:
            return _ok("offline_queue", f"{n} queued (will flush when channels up)")
        return _ok("offline_queue", "empty")
    except Exception as e:
        return _warn("offline_queue", str(e))


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
        check_persistence(),
        check_suid(),
        check_detection_modules(),
        check_firewall_plane(),
        check_offline_queue(),
    ]
    ok = sum(1 for c in checks if c["status"] == "OK")
    warn = sum(1 for c in checks if c["status"] == "WARN")
    fail = sum(1 for c in checks if c["status"] == "FAIL")
    ready = fail == 0 and ok >= 8  # install-ok only; not production certification
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
            elif c["name"] == "persistence":
                result["next"].append("python3 sentinel.py persistence-baseline")
            elif c["name"] == "suid":
                result["next"].append("python3 sentinel.py integrity")
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
        # Security defaults (improvement brief)
        extra = []
        _check_config_perms(extra)
        _check_dashboard_password(extra)
        for e in extra:
            status = e.get("level") or ("OK" if e.get("ok") else "FAIL")
            checks.append({
                "name": e.get("name", "extra"),
                "status": status,
                "detail": e.get("detail", ""),
            })
            if status == "OK":
                ok += 1
            elif status == "WARN":
                warn += 1
            else:
                fail += 1
            if verbose:
                mark = "+" if status == "OK" else ("!" if status == "WARN" else "X")
                print(f"  [{mark}] {status:4}  {e.get('name')}  {e.get('detail')}")
        print(f"  Summary: {ok} OK · {warn} WARN · {fail} FAIL")
        if result["client_ready"]:
            print("  Verdict: INSTALL OK — no FAIL items; review WARNs before production (not a production certification)")
        elif result["ok"]:
            print("  Verdict: INSTALL OK — complete WARNs before production (not production-certified)")
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
