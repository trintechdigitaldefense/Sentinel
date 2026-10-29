#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""SENTINEL installer — dependency check + config init + cases wire.

Usage:
  python3 setup.py
  python3 setup.py --check   # deps only, no write
"""
from __future__ import annotations

import json
import os
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "sentinel.py"
VERSION = "3.16.14"
HOME = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
CONFIG = HOME / "config.json"
DATA = HOME / "data"
LOGS = HOME / "logs"

OPTIONAL = {
    "reportlab": "PDF client reports",
    "requests": "threat intel HTTP (optional)",
}



def ensure_git_clean() -> None:
    """Warn on drift; never hard-reset unless SENTINEL_RECOVER_SYNC=1."""
    import subprocess
    if not (ROOT / ".git").is_dir():
        return
    recover = os.environ.get("SENTINEL_RECOVER_SYNC", "").lower() in ("1", "true", "yes")
    try:
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        print(f"[=] git status skipped: {e}")
        return
    is_dirty = bool((dirty.stdout or "").strip())
    try:
        subprocess.run(["git", "fetch", "origin"], cwd=str(ROOT), capture_output=True, timeout=60)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True, timeout=15
        ).stdout.strip()
        remote = subprocess.run(
            ["git", "rev-parse", "origin/main"], cwd=str(ROOT), capture_output=True, text=True, timeout=15
        ).stdout.strip()
    except Exception:
        head = remote = ""
    behind = bool(head and remote and head != remote)

    if not is_dirty and not behind:
        print(f"[+] Git tree clean @ {(head or '')[:8] or 'unknown'}")
        return

    if is_dirty:
        print("[!] Local uncommitted changes detected — leaving tree untouched")
        print((dirty.stdout or "")[:400])
    if behind:
        print("[!] Branch differs from origin/main")
        print("    Safe upgrade: git pull --ff-only")
        print("    Or:           git merge --ff-only origin/main")

    if recover:
        print("[!] SENTINEL_RECOVER_SYNC=1 — hard reset to origin/main")
        try:
            subprocess.run(["git", "reset", "--hard", "origin/main"], cwd=str(ROOT), check=True)
            print("[+] Recovered to origin/main")
        except Exception as e:
            print(f"[!] reset failed: {e}")
        return

    print("    Recovery (destructive): SENTINEL_RECOVER_SYNC=1 python3 setup.py")



def check_engine() -> bool:
    if not ENGINE.exists():
        print(f"[!] Missing {ENGINE}")
        return False
    try:
        py_compile.compile(str(ENGINE), doraise=True)
    except Exception as e:
        print(f"[!] sentinel.py does not compile: {e}")
        return False
    print(f"[+] Engine OK ({ENGINE.stat().st_size} bytes)")
    return True


def apply_cases_wire() -> None:
    """Wire menu / send_alert / cases command into sentinel.py if needed."""
    script = ROOT / "scripts" / "apply_cases_wire.py"
    if not script.exists():
        print("[=] cases wire script not present — skip")
        return
    try:
        import runpy

        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        if e.code not in (0, None):
            print(f"[!] cases wire exit {e.code}")
    except Exception as e:
        print(f"[!] cases wire: {e}")


def apply_dashboard_cases() -> None:
    """Inject open-cases UI into dashboard.html if needed."""
    script = ROOT / "scripts" / "apply_dashboard_cases.py"
    if not script.exists():
        print("[=] dashboard cases script not present — skip")
        return
    try:
        import runpy

        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        if e.code not in (0, None):
            print(f"[!] dashboard cases exit {e.code}")
    except Exception as e:
        print(f"[!] dashboard cases: {e}")


def check_deps() -> None:
    print("\n[*] Dependency check")
    print(f"    Python {sys.version.split()[0]}")
    for name, why in OPTIONAL.items():
        try:
            __import__(name)
            print(f"  [+] {name} — {why}")
        except ImportError:
            print(f"  [!] {name} missing — optional ({why}). pip install {name}")


def init_dirs() -> None:
    for d in (HOME, DATA, LOGS, DATA / "deception_artifacts", DATA / "integrity_baseline"):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except Exception:
            pass
    print(f"[+] Data dir {HOME}")


def default_config() -> dict:
    return {
        "version": VERSION,
        "client_name": "Client",
        "network": {"subnets": [], "auto_detect": True},
        "alerting": {
            "whatsapp": {"enabled": False, "phone": "", "apikey": ""},
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "from_email": "",
                "to_emails": [],
                "username": "",
                "password": "",
                "use_tls": True,
            },
            "webhook": {"enabled": False, "url": "", "headers": {}},
            "syslog": {"enabled": False, "address": "127.0.0.1", "port": 514},
            "quiet_hours": {"enabled": False, "start": "22:00", "end": "07:00"},
            "dedup_minutes": 15,
        },
        "response": {
            "enabled": False,
            "kill_process": False,
            "block_ip": False,
            "disable_user": False,
        },
        "threat_intel": {
            "enabled": False,
            "abuseipdb_key": "",
            "otx_key": "",
            "cache_hours": 24,
        },
        "dashboard": {
            "port": 8792,
            "bind": "127.0.0.1",
            "username": "admin",
            "password": "",
            "allow_control": False,
        },
        "central": {
            "enabled": False,
            "server_url": "",
            "api_key": "",
            "heartbeat_seconds": 300,
        },
        "logging": {"level": "INFO", "json_files": True, "retention_days": 30},
        "agent": {"shared_token": "", "mode": "standalone"},
    }


def init_config() -> None:
    if CONFIG.exists():
        try:
            existing = json.loads(CONFIG.read_text())
            print(f"[=] Config exists ({CONFIG})")
            base = default_config()
            changed = False
            for k, v in base.items():
                if k not in existing:
                    existing[k] = v
                    changed = True
            if changed:
                CONFIG.write_text(json.dumps(existing, indent=2))
                try:
                    os.chmod(CONFIG, 0o600)
                except Exception:
                    pass
                print("[+] Config merged with new defaults (0600)")
            return
        except Exception as e:
            print(f"[!] Config unreadable ({e}) — rewriting defaults")
    cfg = default_config()
    CONFIG.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG, 0o600)
    except Exception:
        pass
    print(f"[+] Wrote default config → {CONFIG}")


def main() -> None:
    print("=" * 56)
    print(f"  SENTINEL setup  v{VERSION}")
    print("  TrinTech Digital Defense")
    print("=" * 56)
    print(f"Repo: {ROOT}")
    if not check_engine():
        sys.exit(1)
    check_deps()
    if "--check" in sys.argv:
        print("\n[=] Check-only mode — no writes")
        return
    apply_cases_wire()
    apply_dashboard_cases()
    check_engine()
    init_dirs()
    init_config()
    # Refresh self-integrity after install/wires so next run is clean
    try:
        si = HOME / "data" / "self_integrity.json"
        if si.exists():
            si.unlink()
            print("[+] Cleared self-integrity baseline (will recreate on next run)")
    except Exception:
        pass

    print("\n" + "=" * 56)
    print(f"  SETUP COMPLETE  (v{VERSION})")
    print("=" * 56)
    print("  python3 sentinel.py doctor")
    print("  python3 sentinel.py go-live")
    print("  python3 sentinel.py          # interactive menu")
    print("  python3 sentinel.py service-install")
    print("  python3 sentinel.py dashboard")
    print()
    print("  If menu crashes or version looks old:")
    print("    git pull --ff-only   # or SENTINEL_RECOVER_SYNC=1 only if you intend to discard local changes")
    print()


# Ensure SIEM ship-file defaults exist (disabled until enable)
try:
    from modules.siem import enable_defaults
    # only seed config keys; leave enabled=False on first install unless SENTINEL_SIEM=1
    import os as _os
    enable_defaults(_os.environ.get("SENTINEL_SIEM", "").lower() in ("1", "true", "yes"))
except Exception:
    pass

if __name__ == "__main__":
    main()
