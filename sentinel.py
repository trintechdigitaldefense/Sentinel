#!/usr/bin/env python3
"""
Sentinel v2.2.0 — Phase 1 Wired Line of Defense Engine
TrinTech Digital Defense | Cybersecurity Research

Active deception meets persistence hunting and Line of Defense.
Monitors local network for unauthorized devices,
deploys deception artifacts to trap and track intruders,
maintains persistent behavioral monitoring,
and provides comprehensive system integrity, process, network, and user monitoring.
"""

__version__ = "2.9.9"
__author__ = "Jason Junior Ramdharry — TrinTech Digital Defense | v2.2.0 — Phase 1 Wired Line of Defense Engine"
__license__ = "For authorized security testing only"

import sys
import os
import json
import subprocess
import socket
import time
import signal
import logging
import hashlib
import pwd
import re
from pathlib import Path
from datetime import datetime, timedelta
import random
import string
import secrets
import threading
import http.server
import socketserver
import urllib.request
import urllib.parse
from typing import Optional

# Phase 4 — Hard to Copy
try:
    from modules.phase4 import (
        baseline_build, baseline_check, caribbean_scan,
        playbook_get, playbook_list, evidence_pack,
        offline_enqueue, offline_status, offline_flush,
        phase4_self_check, ensure_phase4_defaults,
    )
except ImportError:
    baseline_build = lambda *a, **k: {"ok": False}
    baseline_check = lambda *a, **k: {"ok": False, "anomalies": []}
    caribbean_scan = lambda *a, **k: {"ok": False, "findings": []}
    playbook_get = lambda *a, **k: {"ok": False, "steps": []}
    playbook_list = lambda: []
    evidence_pack = lambda *a, **k: {"ok": False}
    offline_enqueue = lambda *a, **k: {"ok": False}
    offline_status = lambda: {"count": 0}
    offline_flush = lambda *a, **k: {"flushed": 0}
    phase4_self_check = lambda config: {"error": "phase4 missing"}
    ensure_phase4_defaults = lambda c: c or {}


# Phase 1 modules
try:
    from modules.phase1 import (
        quiet_should_emit, auto_quarantine, embed_canary_beacon,
        handle_canary_beacon, client_onboard, phase1_self_check,
        tls_agent_headers, CRITICAL_ALERTS,
    )
except ImportError:
    try:
        from phase1 import (
            quiet_should_emit, auto_quarantine, embed_canary_beacon,
            handle_canary_beacon, client_onboard, phase1_self_check,
            tls_agent_headers, CRITICAL_ALERTS,
        )
    except ImportError:
        quiet_should_emit = lambda config, alert_type, details=None: True
        auto_quarantine = lambda *a, **k: {"actions": []}
        embed_canary_beacon = lambda content, canary_id, central_url="": content + f"\n# SENTINEL-CANARY-ID: {canary_id}\n"
        handle_canary_beacon = lambda *a, **k: {}
        client_onboard = None
        phase1_self_check = lambda config: {"error": "phase1 module missing"}
        tls_agent_headers = lambda token, extra=None: {"Content-Type": "application/json", "X-Sentinel-Token": token or ""}
        CRITICAL_ALERTS = {"REVERSE_SHELL", "CANARY_TRIGGERED", "CANARY_BEACON", "AGENT_REVERSE_SHELL"}


# ── Paths ──
SENTINEL_DIR = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
DATA_DIR = SENTINEL_DIR / "data"
CONFIG_FILE = SENTINEL_DIR / "config.json"
ALERT_LOG = DATA_DIR / "alerts.log"
DEVICE_DB = DATA_DIR / "devices.json"
DECEPTION_DIR = DATA_DIR / "deception_artifacts"
INTEGRITY_DIR = DATA_DIR / "integrity_baseline"
FIM_BASELINE = INTEGRITY_DIR / "integrity_baseline.json"
CRON_BASELINE = DATA_DIR / "cron_baseline.json"
SSH_BLOCKLIST_FILE = DATA_DIR / "iptables_blocklist.json"
SSH_FAIL_LOG = DATA_DIR / "ssh_failures.json"
USER_BASELINE = DATA_DIR / "user_baseline.json"
SUID_BASELINE = DATA_DIR / "suid_baseline.json"
AGENT_DATA_DIR = DATA_DIR / "agents"
SELF_INTEGRITY_FILE = DATA_DIR / "self_integrity.json"
AGENT_PORT = 8743

# ── Logging ──
def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger = logging.getLogger("sentinel")
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


# ── Color helpers ──
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GRAY    = "\033[90m"
    BLUE    = "\033[94m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"


def banner():
    print(f"""
{C.BOLD}{C.CYAN}  _   _      _   _        _     _______ _
 | \\ | |    | \\ | |      | |   |__   __(_)
 | |\\  |  __/ |\\  | (_| || || (_| | |_) | | | | | | |

{C.BOLD}{C.BLUE}SENTINEL{C.RESET} {C.GRAY}v{__version__}{C.RESET}
{C.GRAY}TrinTech Digital Defense — Cybersecurity Research & Tool Repository{C.RESET}
{C.GRAY}Active Deception · Persistence Hunting · Line of Defense{C.RESET}
{C.GRAY}{'_' * 50}{C.RESET}
""")


# ════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════════

def init_config(logger):
    SENTINEL_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DECEPTION_DIR.mkdir(parents=True, exist_ok=True)
    INTEGRITY_DIR.mkdir(parents=True, exist_ok=True)

    default_config = {
        "version": __version__,
        "created": datetime.now().isoformat(),
        "network": {
            "scan_interval": 30,
            "scan_ports": "22,80,443,8080,3306,5432,27017,6379,8443,9200",
            "scan_subnets": ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"],
        },
        "deception": {
            "active": True,
            "fake_services": [
                {"port": 8080, "service": "admin-panel", "banner": "TrinTech Internal Admin Panel"},
                {"port": 3306, "service": "mysql-decoy", "banner": "MySQL 5.7 Database (DECOY)"},
                {"port": 8443, "service": "vpn-gateway", "banner": "Corporate VPN Portal"},
            ],
            "fake_files": True,
            "fake_ssh_banner": True,
        },
        "alerting": {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "from_email": "",
                "app_password": "",
                "to_email": "",
            },
            "log_file": str(ALERT_LOG),
        },
        "persistence": {
            "monitor_interval": 60,
            "alert_on_new_device": True,
            "alert_on_new_port": True,
            "alert_on_auth_failure": True,
        },
        "fim": {
            "active": True,
            "scan_systemd_services": True,
            "scan_suid_binaries": True,
            "scan_ssh_configs": True,
            "scan_passwd": True,
            "scan_cron": True,
        },
        "process_monitor": {
            "active": True,
            "suspicious_commands": ["xmrig", "minerd", "cpuminer", "cspace", "coinhive", "kworkerds"],
            "suspicious_ports": [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337],
            "malware_paths": ["/tmp/", "/var/tmp/", "/dev/shm/"],
            "alert_on_suspicious_process": True,
            "alert_on_unknown_user_process": False,
            "monitored_users": [],
        },
        "ssh_blocking": {
            "active": True,
            "max_failures": 5,
            "time_window": 600,
            "block_duration": 1800,
            "alert_on_block": True,
        },
        "outbound_monitor": {
            "active": True,
            "alert_on_suspicious_port": True,
            "alert_on_foreign_ip": False,
            "known_internal_prefixes": [
                "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "::1",
            ],
        },
        "user_monitor": {
            "active": True,
            "alert_on_new_user": True,
            "alert_on_sudo": True,
            "alert_on_failed_sudo": True,
        },
        "cron_monitor": {
            "active": True,
            "alert_on_new_cron": True,
            "alert_on_modified_cron": True,
        },
        "hardening_audit": {
            "active": True,
            "alert_on_regression": True,
        },
        "agent": {
            "enabled": True,
            "port": 8743,
            "shared_token": "",
            "central_url": "",
            "report_interval": 60,
        },
    }

    config = default_config
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        for key in default_config:
            if key not in config:
                config[key] = default_config[key]
            elif isinstance(default_config[key], dict):
                for subkey, subval in default_config[key].items():
                    if subkey not in config[key]:
                        config[key][subkey] = subval
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Config loaded from {C.BOLD}{CONFIG_FILE}{C.RESET}")
    else:
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        config = default_config
        logger.info(f"{C.GREEN}✓{C.RESET} Config initialized at {C.BOLD}{CONFIG_FILE}{C.RESET}")

    # Ensure agent token exists
    agent_cfg = config.setdefault("agent", {})
    if not agent_cfg.get("shared_token"):
        agent_cfg["shared_token"] = secrets.token_urlsafe(32)
        agent_cfg.setdefault("port", 8743)
        agent_cfg.setdefault("enabled", True)
        agent_cfg.setdefault("report_interval", 60)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Generated agent shared_token")

    # Phase 1 defaults
    config.setdefault("quiet", {
        "enabled": False,
        "min_severity": "medium",
        "suppress_types": [],
        "rate_limit_minutes": 10,
        "whitelist_processes": ["sentinel", "systemd", "sshd"],
        "whitelist_ips": [],
    })
    config.setdefault("quarantine", {
        "enabled": True,
        "on_alerts": ["REVERSE_SHELL", "CANARY_TRIGGERED", "CANARY_BEACON", "AGENT_REVERSE_SHELL"],
        "block_ip": True,
        "kill_process": True,
        "lock_user": False,
    })
    config.setdefault("client", {"name": ""})
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

    return config


def load_config_safe():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"alerting": {"email": {}, "log_file": str(ALERT_LOG)}, "deception": {}, "persistence": {}}


# ════════════════════════════════════════════════════════════════════
# HELPERS (preserved from v1)
# ════════════════════════════════════════════════════════════════════

def load_devices():
    if DEVICE_DB.exists():
        with open(DEVICE_DB) as f:
            return json.load(f)
    return {"devices": {}, "first_seen": {}, "last_seen": {}, "total_scans": 0}


def save_devices(data):
    with open(DEVICE_DB, "w") as f:
        json.dump(data, f, indent=2, default=str)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_my_mac():
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "link/ether" in line:
                return line.split("link/ether ")[1].split()[0]
    except Exception:
        pass
    return "00:00:00:00:00:00"


def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


def send_alert(alert_type, details, logger=None):

    try:
        from modules.phase7 import quiet_should_suppress
        _qs = quiet_should_suppress(str(alert_type))
        if _qs.get("suppress"):
            return
    except Exception:
        pass

    try:
        from modules.phase5 import hygiene_should_emit
        _hy = hygiene_should_emit(str(alert_type), None)
        if not _hy.get("allow", True):
            return
    except Exception:
        pass
    config = load_config_safe()
    # Phase 1: quiet mode filter
    try:
        if not quiet_should_emit(config, alert_type, details):
            return
    except Exception:
        pass
    ts = datetime.now().isoformat()
    alert = {"timestamp": ts, "type": alert_type, "details": details,
             "hostname": socket.gethostname(), "local_ip": get_local_ip()}
    log_file = config.get("alerting", {}).get("log_file", str(ALERT_LOG))
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:
        pass
    # Phase 1: auto-quarantine on critical alerts
    try:
        if alert_type in CRITICAL_ALERTS or alert_type in set(config.get("quarantine", {}).get("on_alerts", [])):
            auto_quarantine(config, alert_type, details if isinstance(details, dict) else {"raw": details},
                            logger=logger, run_cmd=run_cmd, send_alert=None)
    except Exception:
        pass
    email_cfg = config.get("alerting", {}).get("email", {})
    if email_cfg.get("enabled", False) and email_cfg.get("from_email") and email_cfg.get("to_email"):
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            msg["From"] = email_cfg["from_email"]
            msg["To"] = email_cfg["to_email"]
            msg["Subject"] = f"[ALERT] Sentinel: {alert_type}"
            msg.attach(MIMEText(
                f"SENTINEL SECURITY ALERT\nType: {alert_type}\nTime: {ts}\nHost: {socket.gethostname()}\nIP: {get_local_ip()}\nDetails: {json.dumps(details, indent=2)}\n", "plain"))
            smtp = smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"])
            smtp.starttls()
            smtp.login(email_cfg["from_email"], email_cfg.get("app_password", ""))
            smtp.sendmail(email_cfg["from_email"], email_cfg["to_email"], msg.as_string())
            smtp.quit()
            if logger:
                logger.info(f"{C.GREEN}✓{C.RESET} Alert sent via email: {C.BOLD}{alert_type}{C.RESET}")
        except Exception as e:
            if logger:
                logger.warning(f"{C.YELLOW}!{C.RESET} Email alert failed: {e}")


def sha256_file(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def is_internal_ip(ip):
    prefixes = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127."]
    return any(ip.startswith(p) for p in prefixes)


# ════════════════════════════════════════════════════════════════════
# MODULE 1: FILESYSTEM INTEGRITY MONITORING (FIM)
# ════════════════════════════════════════════════════════════════════

def fim_build_baseline(config, logger):
    fim = config.get("fim", {})
    if not fim.get("active", True):
        return

    logger.info(f"{C.CYAN}[*]{C.RESET} FIM module active — building baseline...")

    baseline = {}
    checked = 0
    skipped = 0

    critical_files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
        "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
        "/etc/profile", "/etc/bash.bashrc", "/root/.bashrc",
        "/root/.ssh/authorized_keys",
        "/usr/bin/sudo", "/usr/bin/passwd", "/bin/su",
        "/sbin/init", "/sbin/reboot", "/etc/crontab",
    ]

    for fpath in critical_files:
        if os.path.exists(fpath):
            checksum = sha256_file(fpath)
            try:
                st = os.stat(fpath)
                baseline[fpath] = {"checksum": checksum, "size": st.st_size, "mode": oct(st.st_mode)[-3:]}
            except Exception:
                baseline[fpath] = {"checksum": checksum}
            checked += 1
        else:
            skipped += 1

    # Systemd services
    if fim.get("scan_systemd_services", True):
        try:
            for root, dirs, files in os.walk("/etc/systemd/system"):
                for f in files:
                    fpath = os.path.join(root, f)
                    if fpath not in baseline:
                        checksum = sha256_file(fpath)
                        if checksum:
                            try:
                                st = os.stat(fpath)
                                baseline[fpath] = {"checksum": checksum, "size": st.st_size, "mode": oct(st.st_mode)[-3:]}
                            except Exception:
                                baseline[fpath] = {"checksum": checksum}
                            checked += 1
        except Exception:
            pass

    # SUID binaries
    if fim.get("scan_suid_binaries", True):
        try:
            result = run_cmd(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "/6000", "-type", "f"], timeout=10)
            for line in result.strip().split("\n"):
                if line.strip():
                    fpath = line.strip()
                    if fpath not in baseline:
                        checksum = sha256_file(fpath)
                        if checksum:
                            try:
                                st = os.stat(fpath)
                                baseline[fpath] = {"checksum": checksum, "size": st.st_size, "mode": oct(st.st_mode)[-3:]}
                            except Exception:
                                baseline[fpath] = {"checksum": checksum}
                            checked += 1
        except Exception:
            pass

    with open(FIM_BASELINE, "w") as f:
        json.dump(baseline, f, indent=2)

    logger.info(f"{C.GREEN}✓{C.RESET} Baseline created: {C.BOLD}{checked} files{C.RESET} tracked ({C.RED}{skipped} skipped/missing{C.RESET})")
    logger.info(f"{C.GREEN}✓{C.RESET} Saved to {C.BOLD}{FIM_BASELINE}{C.RESET}")


def fim_check(config, logger):
    fim = config.get("fim", {})
    if not fim.get("active", True):
        return []

    logger.info(f"{C.CYAN}[*]{C.RESET} FIM module active")
    logger.info(f"{C.CYAN}[*]{C.RESET} Running integrity check against existing baseline...")

    try:
        with open(FIM_BASELINE) as f:
            baseline = json.load(f)
    except Exception:
        logger.warning(f"{C.YELLOW}!{C.RESET} No FIM baseline found. Run: {C.BOLD}sentinel integrity{C.RESET}")
        return []

    changes = []

    for fpath, bl in baseline.items():
        if not os.path.exists(fpath):
            msg = f"{C.RED}⚠ FIM:{C.RESET} {C.BOLD}{fpath}{C.RESET} is a {C.RED}DELETED{C.RESET} file"
            logger.warning(msg)
            changes.append({"file": fpath, "type": "deleted"})
            send_alert("FIM_DELETED", {"file": fpath}, logger)
            continue

        checksum = sha256_file(fpath)
        if checksum and checksum != bl.get("checksum"):
            msg = f"{C.RED}⚠ FIM:{C.RESET} {C.BOLD}{fpath}{C.RESET} has been {C.RED}MODIFIED{C.RESET} (checksum changed)"
            logger.warning(msg)
            changes.append({"file": fpath, "type": "modified", "old": bl.get("checksum", "")[:16], "new": checksum[:16]})
            send_alert("FIM_MODIFIED", {"file": fpath, "old_checksum": bl.get("checksum", ""), "new_checksum": checksum}, logger)

    if changes:
        logger.info(f"{C.RED}✗{C.RESET} {C.BOLD}{len(changes)} integrity changes{C.RESET} detected")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} All {C.BOLD}{len(baseline)} files{C.RESET} integrity verified")

    return changes


def fim_watch(config, logger):
    fim = config.get("fim", {})
    if not fim.get("active", True):
        return

    dirs = ["/etc/", "/root/", "/tmp/", "/var/log/"]
    decoy_dirs = [
        str(Path.home() / "Desktop" / ".ssh"),
        str(Path.home() / "Documents"),
        str(Path.home() / "Downloads"),
    ]
    for d in decoy_dirs:
        if os.path.isdir(d) and d not in dirs:
            dirs.append(d)

    logger.info(f"{C.CYAN}[*]{C.RESET} Starting real-time filesystem watcher: {', '.join(dirs)}")

    try:
        for dirpath in dirs:
            if not os.path.isdir(dirpath):
                logger.warning(f"{C.YELLOW}!{C.RESET} Not a directory: {C.BOLD}{dirpath}{C.RESET}")
                continue
            try:
                result = subprocess.run(
                    ["inotifywait", "-q", "-m", "-r", "--format", "%e %w%f",
                     "-e", "modify,create,delete", dirpath],
                    capture_output=True, text=True, timeout=3600
                )
                for line in result.stdout.split("\n"):
                    if not line.strip() or "sentinel" in line.lower():
                        continue
                    parts = line.strip().split(" ", 1)
                    if len(parts) == 2:
                        event, filepath = parts
                        if "/var/log" in dirpath and "DELETE" in event:
                            logger.warning(f"{C.RED}⚠ LOG TAMPERING:{C.RESET} {C.BOLD}{event}{C.RESET} — {C.BOLD}{filepath}{C.RESET}")
                            send_alert("LOG_TAMPERING", {"event": event, "file": filepath}, logger)
                        else:
                            logger.warning(f"{C.YELLOW}!{C.RESET} {C.BOLD}{event}{C.RESET}: {C.BOLD}{filepath}{C.RESET}")
                            send_alert("FIM_REALTIME", {"event": event, "file": filepath}, logger)
            except subprocess.TimeoutExpired:
                logger.info(f"{C.GREEN}✓{C.RESET} Watcher timeout (1hr)")
                break
            except FileNotFoundError:
                logger.warning(f"{C.YELLOW}!{C.RESET} inotifywait not installed: apt-get install -y inotify-tools")
                break
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.warning(f"{C.YELLOW}!{C.RESET} Watch error on {C.BOLD}{dirpath}{C.RESET}: {e}")
    except KeyboardInterrupt:
        logger.info(f"{C.GREEN}✓{C.RESET} Filesystem watcher stopped")


# ════════════════════════════════════════════════════════════════════
# MODULE 2: PROCESS MONITORING
# ════════════════════════════════════════════════════════════════════

def process_scan(config, logger):
    pm = config.get("process_monitor", {})
    if not pm.get("active", True):
        return []

    suspicious = []
    RS_PATTERNS = [
        r"bash\s+-i", r"/dev/tcp/", r"nc\s+.*-e", r"ncat\s+.*-e",
        r"python[23]?\s+-c\s+[\"'].*socket", r"perl\s+-e\s+[\"'].*socket",
        r"php\s+-r\s+[\"'].*fsockopen", r"ruby\s+-rsocket", r"socat\s+.*exec",
        r"awk\s+.*[/]dev[/]tcp", r"lua\s+-e\s+[\"'].*socket",
        r"mkfifo\s+/tmp/", r"tee\s+/dev/tcp", r"xterm\s+-display",
        r"sh\s+-i", r"dash\s+-i", r"zsh\s+-i"
    ]

    try:
        result = run_cmd(["ps", "auxww", "--no-headers"], timeout=10)
        for line in result.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 11:
                continue

            user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
            command = " ".join(parts[10:])

            if "sentinel" in command.lower():
                continue

            for pat in RS_PATTERNS:
                if re.search(pat, command, re.I):
                    msg = f"{C.RED}⚠ REVERSE SHELL DETECTED:{C.RESET} {C.BOLD}{command[:100]}{C.RESET}"
                    msg += f"\n     PID={pid} User={user} Pattern={pat}"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "reverse_shell", "pattern": pat})
                    send_alert("REVERSE_SHELL", {"pid": pid, "user": user, "command": command[:200], "pattern": pat}, logger)
                    break

            for susp_cmd in pm.get("suspicious_commands", []):
                if susp_cmd in command:
                    msg = f"{C.RED}⚠ SUSPICIOUS PROCESS:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                    msg += f"\n     PID={pid} User={user} CPU={cpu}%"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "suspicious_cmd"})
                    send_alert("SUSPICIOUS_PROCESS", {"pid": pid, "user": user, "command": command[:200], "matched": susp_cmd}, logger)
                    break

            # Only flag if the *executable* lives under a malware path — not if
            # the command line merely mentions /tmp (e.g. curl writing a file there).
            exe = command.split()[0] if command.split() else ""
            allow_bin = pm.get("allowlist_bins", [
                "curl", "wget", "git", "ssh", "scp", "rsync", "python", "python3",
                "bash", "sh", "dash", "zsh", "node", "npm", "pip", "pip3", "apt",
                "dpkg", "systemctl", "journalctl", "ps", "top", "htop", "ss", "ip",
            ])
            exe_base = exe.rsplit("/", 1)[-1]
            system_prefixes = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")
            if any(exe.startswith(p) for p in system_prefixes) or exe_base in allow_bin:
                pass  # skip malware_path check for known-good
            else:
                for mpath in pm.get("malware_paths", ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                    if exe.startswith(mpath) or (mpath.rstrip("/") and exe.startswith(mpath.rstrip("/"))):
                        msg = f"{C.RED}⚠ PROCESS FROM MALWARE PATH:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                        logger.warning(msg)
                        suspicious.append({"pid": pid, "user": user, "command": command, "reason": "malware_path", "exe": exe})
                        send_alert("MALWARE_PATH_PROCESS", {"pid": pid, "user": user, "command": command[:200], "path": mpath, "exe": exe}, logger)
                        break

            try:
                if float(cpu) > 80:
                    msg = f"{C.YELLOW}!{C.RESET} HIGH CPU ({cpu}%): {C.BOLD}{command[:60]}{C.RESET}"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "high_cpu", "cpu": float(cpu)})
            except ValueError:
                pass

    except Exception as e:
        logger.warning(f"{C.YELLOW}!{C.RESET} Process scan failed: {e}")

    if suspicious:
        logger.info(f"{C.RED}⚠{C.RESET} {C.BOLD}{len(suspicious)} suspicious process(es){C.RESET}")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} Process scan clean")
    return suspicious


# ════════════════════════════════════════════════════════════════════
# MODULE 3: SSH BRUTE FORCE DETECTION & AUTO-BLOCKING
# ════════════════════════════════════════════════════════════════════

def _load_blocklist():
    if SSH_BLOCKLIST_FILE.exists():
        with open(SSH_BLOCKLIST_FILE) as f:
            return json.load(f)
    return {"blocked": {}}


def _save_blocklist(data):
    with open(SSH_BLOCKLIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


def ssh_blocking_check(config, logger):
    ssh = config.get("ssh_blocking", {})
    if not ssh.get("active", True):
        return []

    blocked_count = 0
    failures = {}

    auth_output = run_cmd(["journalctl", "-u", "ssh", "--since", "1 hour ago", "-n", "500"], timeout=10)
    if not auth_output.strip() and os.path.exists("/var/log/auth.log"):
        try:
            with open("/var/log/auth.log") as f:
                auth_output = f.read()
        except Exception:
            pass

    if auth_output:
        for line in auth_output.split("\n"):
            if "Failed password" in line or "authentication failure" in line:
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    failures[ip] = failures.get(ip, 0) + 1

    max_failures = ssh.get("max_failures", 5)
    block_duration = ssh.get("block_duration", 1800)

    for ip, count in failures.items():
        if count >= max_failures:
            blocklist = _load_blocklist()
            now = datetime.now()

            if ip in blocklist.get("blocked", {}):
                try:
                    bt = datetime.fromisoformat(blocklist["blocked"][ip].get("block_until", ""))
                    if now < bt:
                        continue
                except Exception:
                    pass

            r = subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", capture_output=True, text=True, shell=True)
            if r.returncode == 0:
                blocklist.setdefault("blocked", {})[ip] = {
                    "reason": f"SSH brute force: {count} failures",
                    "failures": count,
                    "blocked_at": now.isoformat(),
                    "block_until": (now + timedelta(seconds=block_duration)).isoformat(),
                }
                _save_blocklist(blocklist)
                blocked_count += 1
                msg = f"{C.RED}🚫 IP BLOCKED:{C.RESET} {C.BOLD}{ip}{C.RESET} ({count} failures) — iptables DROP for {block_duration}s"
                logger.warning(msg)
                send_alert("IP_BLOCKED", {"ip": ip, "failures": count, "reason": "SSH brute force"}, logger)
            else:
                logger.warning(f"{C.YELLOW}!{C.RESET} Failed to block {C.BOLD}{ip}{C.RESET}: {r.stderr[:100]}")

    if blocked_count > 0:
        logger.info(f"{C.RED}🚫{C.RESET} {C.BOLD}{blocked_count} IP(s){C.RESET} blocked via iptables")
    elif failures:
        logger.info(f"{C.GREEN}✓{C.RESET} SSH scan: {C.BOLD}{len(failures)} IP(s){C.RESET} with failures (none exceeded threshold)")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} SSH scan: no failures detected")

    return {"total_failures": len(failures), "blocked_count": blocked_count}


# ════════════════════════════════════════════════════════════════════
# MODULE 4: OUTBOUND CONNECTION MONITORING
# ════════════════════════════════════════════════════════════════════

def outbound_scan(config, logger):
    om = config.get("outbound_monitor", {})
    if not om.get("active", True):
        return []

    suspicious = []
    suspicious_ports = om.get("suspicious_ports", [])

    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            local_addr, remote_addr, state = parts[1], parts[2], parts[3]
            if state != "01":
                continue

            try:
                li, lp = local_addr.split(":")
                ri, rp = remote_addr.split(":")
                remote_ip = str(int(ri, 16))
                remote_port = int(rp, 16)
            except ValueError:
                continue

            if remote_port in suspicious_ports:
                msg = f"{C.RED}⚠ SUSPICIOUS OUTBOUND PORT:{C.RESET} {C.BOLD}{remote_ip}:{remote_port}{C.RESET} (common reverse shell port)"
                logger.warning(msg)
                suspicious.append({"remote": f"{remote_ip}:{remote_port}", "port": remote_port, "reason": "suspicious_port"})
                send_alert("OUTBOUND_SUSPICIOUS_PORT", {"remote": f"{remote_ip}:{remote_port}", "port": remote_port}, logger)

            if remote_port > 1024 and not is_internal_ip(remote_ip) and om.get("alert_on_foreign_ip", False):
                msg = f"{C.YELLOW}!{C.RESET} Foreign outbound: {C.BOLD}{remote_ip}:{remote_port}{C.RESET}"
                logger.warning(msg)
                suspicious.append({"remote": f"{remote_ip}:{remote_port}", "reason": "foreign_ip"})

    except Exception as e:
        logger.warning(f"{C.YELLOW}!{C.RESET} Outbound scan failed: {e}")

    if suspicious:
        logger.info(f"{C.RED}⚠{C.RESET} {C.BOLD}{len(suspicious)} suspicious outbound connection(s){C.RESET}")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} Outbound scan clean")

    return suspicious


# ════════════════════════════════════════════════════════════════════
# MODULE 5: USER ACCOUNT MONITORING
# ════════════════════════════════════════════════════════════════════

def user_monitor_check(config, logger):
    um = config.get("user_monitor", {})
    if not um.get("active", True):
        return []

    changes = []

    try:
        with open("/etc/passwd") as f:
            users = []
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    uid = int(parts[2])
                    if uid >= 1000 and parts[0] != "nobody":
                        users.append(parts[0])
    except Exception:
        pass

    sudo_output = run_cmd(["journalctl", "-u", "sudo", "--since", "1 hour ago", "-n", "50"], timeout=10)
    if not sudo_output.strip() and os.path.exists("/var/log/auth.log"):
        sudo_output = run_cmd(["grep", "-i", "sudo", "/var/log/auth.log"], timeout=5)

    if sudo_output:
        for line in sudo_output.strip().split("\n"):
            if "COMMAND=" in line:
                cmd = line.split("COMMAND=", 1)[1]
                user_match = re.search(r"user=(\w+)", line)
                username = user_match.group(1) if user_match else "unknown"
                if um.get("alert_on_sudo", True):
                    msg = f"{C.YELLOW}!{C.RESET} {C.BOLD}SUDO:{C.RESET} {C.BOLD}{username}{C.RESET} → {C.BOLD}{cmd[:100]}{C.RESET}"
                    logger.warning(msg)
                    changes.append({"type": "sudo", "user": username, "cmd": cmd[:200]})
                    send_alert("SUDO_USAGE", {"user": username, "command": cmd[:200]}, logger)
            elif "FAILED" in line.upper() and ("sudo" in line.lower() or "su " in line):
                user_match = re.search(r"user=(\w+)", line)
                username = user_match.group(1) if user_match else "unknown"
                if um.get("alert_on_failed_sudo", True):
                    msg = f"{C.RED}⚠ FAILED SUDO:{C.RESET} {C.BOLD}{username}{C.RESET}"
                    logger.warning(msg)
                    changes.append({"type": "failed_sudo", "user": username})
                    send_alert("FAILED_SUDO", {"user": username}, logger)

    if changes:
        logger.info(f"{C.GREEN}✓{C.RESET} User monitor: {C.BOLD}{len(changes)} event(s){C.RESET}")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} User monitor: no events")

    return changes


# ════════════════════════════════════════════════════════════════════
# MODULE 6: CRON & SCHEDULED TASK INTEGRITY
# ════════════════════════════════════════════════════════════════════

def cron_monitor_check(config, logger):
    cm = config.get("cron_monitor", {})
    if not cm.get("active", True):
        return []

    changes = []
    current = []

    try:
        cr = run_cmd(["crontab", "-l"], timeout=5)
        for line in cr.strip().split("\n"):
            if line.strip() and not line.startswith("#"):
                current.append({"source": "root_crontab", "entry": line.strip()[:200]})
    except Exception:
        pass

    if os.path.exists("/etc/crontab"):
        try:
            with open("/etc/crontab") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        current.append({"source": "etc_crontab", "entry": line.strip()[:200]})
        except Exception:
            pass

    try:
        for entry in os.listdir("/etc/cron.d/"):
            fpath = f"/etc/cron.d/{entry}"
            if os.path.isfile(fpath):
                try:
                    with open(fpath) as f:
                        for line in f:
                            if line.strip() and not line.startswith("#"):
                                current.append({"source": f"cron.d/{entry}", "entry": line.strip()[:200]})
                except Exception:
                    pass
    except Exception:
        pass

    try:
        with open(CRON_BASELINE) as f:
            baseline = json.load(f)
    except Exception:
        with open(CRON_BASELINE, "w") as f:
            json.dump(current, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Cron baseline created: {C.BOLD}{len(current)} entries{C.RESET}")
        return []

    baseline_set = {c["entry"] for c in baseline}
    current_set = {c["entry"] for c in current}

    for entry in current_set - baseline_set:
        msg = f"{C.RED}⚠ NEW CRON:{C.RESET} {C.BOLD}{entry[:100]}{C.RESET}"
        logger.warning(msg)
        changes.append({"type": "new", "entry": entry[:200]})
        send_alert("NEW_CRON", {"entry": entry[:200]}, logger)

    for entry in baseline_set - current_set:
        msg = f"{C.YELLOW}!{C.RESET} {C.BOLD}REMOVED CRON:{C.RESET} {C.BOLD}{entry[:100]}{C.RESET}"
        logger.warning(msg)
        changes.append({"type": "removed", "entry": entry[:200]})
        send_alert("REMOVED_CRON", {"entry": entry[:200]}, logger)

    if not changes:
        logger.info(f"{C.GREEN}✓{C.RESET} Cron integrity verified")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} Cron integrity: {C.BOLD}{len(changes)} change(s){C.RESET}")

    return changes


# ════════════════════════════════════════════════════════════════════
# MODULE 7: SYSTEM HARDENING AUDIT
# ════════════════════════════════════════════════════════════════════

def hardening_audit(config, logger):
    ha = config.get("hardening_audit", {})
    if not ha.get("active", True):
        return {"score": 0, "issues": []}

    issues = []
    score = 100

    # 1. SSH PermitRootLogin
    if os.path.exists("/etc/ssh/sshd_config"):
        content = run_cmd(["cat", "/etc/ssh/sshd_config"], timeout=5)
        if "PermitRootLogin yes" in content:
            issues.append({"issue": "SSH root login enabled", "severity": "critical", "penalty": 10})
            score -= 10
        elif "PermitRootLogin" not in content and content.strip():
            issues.append({"issue": "SSH root login not explicitly disabled", "severity": "warning", "penalty": 5})
            score -= 5

        if "PasswordAuthentication yes" in content:
            issues.append({"issue": "SSH password authentication enabled", "severity": "warning", "penalty": 5})
            score -= 5

    # 2. Firewall
    iptables_out = run_cmd(["iptables", "-L", "-n"], timeout=5)
    if not iptables_out.strip() or "Chain INPUT" not in iptables_out:
        issues.append({"issue": "No iptables rules — no firewall active", "severity": "critical", "penalty": 15})
        score -= 15

    # 3. World-writable config files in /etc
    try:
        ww = run_cmd(
            ["find", "/etc", "-maxdepth", "2", "-writable", "-not", "-type", "l", "-not", "-type", "d",
             "-not", "-path", "*/snap/*", "-not", "-path", "*/systemd/*",
             "-not", "-name", "*.driver", "-not", "-name", "*.conffiles",
             "-name", "*.conf", "-o", "-name", "*.cfg", "-o", "-name", "*.sh",
             "-o", "-name", "*.service", "-o", "-name", "*.socket"],
            timeout=10
        )
        files = [l for l in ww.strip().split("\n") if l.strip()]
        if len(files) > 3:
            issues.append({"issue": f"{len(files)} world-writable config files in /etc", "severity": "warning", "penalty": 3})
            score -= 3
    except Exception:
        pass

    # 4. SUID binaries count
    try:
        suid = run_cmd(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "/4000", "-type", "f"], timeout=10)
        count = len([l for l in suid.strip().split("\n") if l.strip()]) if suid.strip() else 0
        if count > 20:
            issues.append({"issue": f"{count} SUID binaries (unusual — may indicate backdoor)", "severity": "warning", "penalty": 5})
            score -= 5
    except Exception:
        pass

    # 5. Core dumps
    core = run_cmd(["sysctl", "kernel.core_pattern"], timeout=5)
    if "/tmp/" in core or "/var/tmp/" in core:
        issues.append({"issue": "Core dumps pointed to writable temp dir", "severity": "warning", "penalty": 3})
        score -= 3

    # 6. Empty passwords
    if os.path.exists("/etc/shadow"):
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] == "":
                        issues.append({"issue": f"Empty password: {parts[0]}", "severity": "critical", "penalty": 10})
                        score -= 10
        except Exception:
            pass

    score = max(0, score)

    if score < 70:
        logger.warning(f"{C.RED}⚠ SECURITY RISK:{C.RESET} Score {C.BOLD}{C.RED}{score}/100{C.RESET} — {C.BOLD}{len(issues)} issue(s){C.RESET}")
    elif score < 90:
        logger.warning(f"{C.YELLOW}!{C.RESET} Hardening: Score {C.BOLD}{C.YELLOW}{score}/100{C.RESET} — {C.BOLD}{len(issues)} issue(s){C.RESET}")
    else:
        logger.info(f"{C.GREEN}✓{C.RESET} System hardening: Score {C.BOLD}{C.GREEN}{score}/100{C.RESET}")

    for issue in issues:
        sev = C.RED if issue["severity"] == "critical" else C.YELLOW
        logger.warning(f"  {sev}●{C.RESET} [{issue['severity'].upper()}] {issue['issue']}")

    # Check for regression
    try:
        with open(DATA_DIR / "hardening_baseline.json") as f:
            prev = json.load(f)
        prev_score = prev.get("score", 100)
        if score < prev_score - 10:
            logger.warning(f"{C.RED}⚠ SECURITY REGRESSION:{C.RESET} Score dropped {C.BOLD}{prev_score}{C.RESET} → {C.BOLD}{score}{C.RESET}")
            send_alert("SECURITY_REGRESSION", {"old_score": prev_score, "new_score": score}, logger)
    except Exception:
        pass

    with open(DATA_DIR / "hardening_baseline.json", "w") as f:
        json.dump({"score": score, "timestamp": datetime.now().isoformat()}, f)

    return {"score": score, "issues": issues, "issue_count": len(issues)}


# ════════════════════════════════════════════════════════════════════
# NETWORK SCANNER (preserved from v1)
# ════════════════════════════════════════════════════════════════════

def scan_network(config, logger, data=None):
    subnets = config.get("network", {}).get("scan_subnets", ["192.168.1.0/24"])
    effective = [s for s in subnets if int(s.split("/")[1]) not in (12, 11, 10)]
    if not effective:
        effective = ["192.168.1.0/24"]
    subnets = effective
    ports = config.get("network", {}).get("scan_ports", "22,80,443,8080")
    local_ip = get_local_ip()
    my_mac = get_my_mac()
    discovered = []
    first_seen = (data or {}).get("first_seen", {})
    last_seen = (data or {}).get("last_seen", {})
    data = data or {"devices": {}, "first_seen": {}, "last_seen": {}, "total_scans": 0}

    logger.info(f"{C.CYAN}[*]{C.RESET} Scanning {len(subnets)} subnets: {', '.join(subnets)}")
    logger.info(f"{C.CYAN}[*]{C.RESET} Ports: {ports}")

    try:
        for subnet in subnets:
            cmd = ["nmap", "-sn", "-oJ", "/tmp/sentinel_scan.json",
                   "--host-timeout", "2s", "--min-rate", "1000", "-T4", "--send-ip", subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                if "timeout" in result.stderr.lower() or "timed out" in result.stderr.lower():
                    logger.warning(f"{C.YELLOW}!{C.RESET} Scan of {C.BOLD}{subnet}{C.RESET} timed out (no response — may be isolated container)")
                else:
                    logger.warning(f"{C.YELLOW}!{C.RESET} Scan of {C.BOLD}{subnet}{C.RESET} failed: {result.stderr[:100]}")
                if os.path.exists("/tmp/sentinel_scan.json"):
                    os.remove("/tmp/sentinel_scan.json")
                continue

            if os.path.exists("/tmp/sentinel_scan.json"):
                with open("/tmp/sentinel_scan.json") as f:
                    scan_data = json.load(f)
                for host in scan_data.get("scanresults", {}).get("hosts", []):
                    ipv4 = host.get("addresses", {}).get("ipv4", {}).get("addr", "")
                    mac = host.get("addresses", {}).get("mac", "N/A")
                    vendor = host.get("addresses", {}).get("mac", {}).get("vendor", "Unknown")
                    hostname = host.get("hostnames", {}).get("hostname", [{}])[0].get("name", "")
                    status = host.get("status", {}).get("state", "unknown")

                    if status == "up" and ipv4:
                        device = {
                            "ip": ipv4, "mac": mac, "hostname": hostname or ipv4,
                            "vendor": vendor if vendor != "Unknown" else "Unknown",
                            "ports": [],
                            "first_seen": first_seen.get(ipv4, datetime.now().isoformat()),
                            "last_seen": datetime.now().isoformat(),
                        }

                        port_cmd = ["nmap", "-sV", "-p", ports, "-oJ", "/tmp/sentinel_ports.json",
                                    "--host-timeout", "2s", "--min-rate", "500", "-T4", ipv4]
                        pr = subprocess.run(port_cmd, capture_output=True, text=True, timeout=30)
                        if pr.returncode == 0 and os.path.exists("/tmp/sentinel_ports.json"):
                            with open("/tmp/sentinel_ports.json") as f:
                                pdata = json.load(f)
                            for h in pdata.get("scanresults", {}).get("hosts", []):
                                for port in h.get("ports", {}).get("port", []):
                                    device["ports"].append({
                                        "port": port.get("portid", ""),
                                        "state": port.get("state", {}).get("state", "closed"),
                                        "service": port.get("service", {}).get("name", "unknown"),
                                        "version": port.get("service", {}).get("product", "")
                                    })

                        if ipv4 != local_ip:
                            if ipv4 not in first_seen:
                                logger.warning(f"{C.RED}⚠ NEW DEVICE DETECTED{C.RESET} — {device['hostname']} ({ipv4})")
                                send_alert("NEW_DEVICE", device, logger)
                            first_seen[ipv4] = datetime.now().isoformat()
                            last_seen[ipv4] = datetime.now().isoformat()

                        discovered.append(device)

                if os.path.exists("/tmp/sentinel_scan.json"):
                    os.remove("/tmp/sentinel_scan.json")

        data["devices"] = {d["ip"]: d for d in discovered}
        data["first_seen"] = first_seen
        data["last_seen"] = last_seen
        data["total_scans"] = data.get("total_scans", 0) + 1
        save_devices(data)

        logger.info(f"{C.GREEN}✓{C.RESET} Scanned {len(subnets)} subnets — {C.BOLD}{len(discovered)} devices{C.RESET} discovered")
        return discovered

    except FileNotFoundError:
        logger.warning(f"{C.YELLOW}!{C.RESET} nmap not found. Install with: apt-get install -y nmap")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"{C.RED}✗{C.RESET} Scan timed out")
        return []
    except Exception as e:
        logger.error(f"{C.RED}✗{C.RESET} Scan failed: {e}")
        return []


# ════════════════════════════════════════════════════════════════════
# DECEPTION (preserved from v1)
# ════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════
# PERSISTENCE HUNTING (enhanced v2)
# ════════════════════════════════════════════════════════════════════

def persistence_hunt(config, logger):
    interval = config.get("persistence", {}).get("monitor_interval", 60)

    try:
        result = run_cmd(["journalctl", "-u", "ssh", "--since", "1 hour ago", "-n", "100"], timeout=10)
        auth_failures = [l for l in result.split("\n") if "Failed password" in l]
        if auth_failures:
            logger.warning(f"{C.RED}!{C.RESET} {C.BOLD}{len(auth_failures)} SSH auth failures{C.RESET}")
            if config.get("persistence", {}).get("alert_on_auth_failure", True):
                send_alert("AUTH_FAILURE", {"failures": len(auth_failures)}, logger)
    except Exception:
        pass

    # Tracker JSON is expected to change when decoys are deployed — do not alert on it.
    # Real canary file changes are detected via canary watcher / FIM, not this path.

    fim_check(config, logger)
    process_scan(config, logger)
    ssh_blocking_check(config, logger)
    outbound_scan(config, logger)
    user_monitor_check(config, logger)
    cron_monitor_check(config, logger)

    return True


# ════════════════════════════════════════════════════════════════════
# REPORTING & STATUS
# ════════════════════════════════════════════════════════════════════

def generate_report(data, config, logger):
    devices = data.get("devices", {})
    total_scans = data.get("total_scans", 0)

    alert_count = 0
    if ALERT_LOG.exists():
        try:
            with open(ALERT_LOG) as f:
                alert_count = sum(1 for line in f if line.strip())
        except Exception:
            pass

    blocked = _load_blocklist().get("blocked", {})
    blocked_count = len(blocked)

    fim_ok = False
    try:
        if FIM_BASELINE.exists():
            with open(FIM_BASELINE) as f:
                fim_ok = len(json.load(f)) > 0
    except Exception:
        pass

    score = 100
    try:
        with open(DATA_DIR / "hardening_baseline.json") as f:
            score = json.load(f).get("score", 100)
    except Exception:
        pass

    score_color = C.GREEN if score >= 80 else C.YELLOW if score >= 60 else C.RED

    print(f"""

{C.BOLD}{'=' * 60}
{C.BOLD}{C.CYAN}  SENTINEL v{__version__} REPORT{C.RESET}
{C.BOLD}{'=' * 60}
{C.BOLD}Generated:{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{C.BOLD}Host:{C.RESET}       {socket.gethostname()}
{C.BOLD}IP:{C.RESET}         {get_local_ip()}
{C.BOLD}MAC:{C.RESET}        {get_my_mac()}
{C.BOLD}{'=' * 60}{C.RESET}

{C.BOLD}DEFENSE STATUS:{C.RESET}
  {C.BOLD}Scans:{C.RESET}       {total_scans}
  {C.BOLD}Devices:{C.RESET}      {C.BOLD}{len(devices)}{C.RESET}
  {C.BOLD}Alerts:{C.RESET}       {C.BOLD}{C.RED if alert_count > 0 else C.GREEN}{alert_count}{C.RESET}
  {C.BOLD}Blocked IPs:{C.RESET}  {C.BOLD}{C.RED if blocked_count > 0 else C.GREEN}{blocked_count}{C.RESET}
  {C.BOLD}Integrity:{C.RESET}    {C.GREEN if fim_ok else C.RED}{'Baseline Active' if fim_ok else 'No Baseline'}{C.RESET}
  {C.BOLD}Hardening:{C.RESET}    {C.BOLD}{score_color}{score}/100{C.RESET}
  {C.BOLD}{'=' * 60}{C.RESET}
""")

    if devices:
        print(f"{C.BOLD}{C.BLUE}DISCOVERED DEVICES{C.RESET}")
        print(f"{'─' * 60}")
        for ip, dev in sorted(devices.items()):
            age = (datetime.now() - datetime.fromisoformat(dev["last_seen"])).days
            age_str = f"{age}d" if age > 0 else "today"
            ports_info = ", ".join(
                f"{p['port']}/{p['service']}" for p in dev.get("ports", []) if p.get("state") == "open"
            ) or "none"
            sc = C.GREEN
            if "decoy" in dev.get("hostname", "").lower():
                sc = C.YELLOW
            print(f"""
  {C.BOLD}{sc}●{C.RESET} {C.BOLD}{dev['hostname'] or ip}{C.RESET}
    IP:   {ip} | MAC: {dev.get('mac', 'N/A')} | Vendor: {dev.get('vendor', 'N/A')}
    Ports: {ports_info} | Last: {dev['last_seen'][:19]} ({age_str})""")
        print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
    else:
        print(f"\n{C.BOLD}{C.YELLOW}No devices yet. Run 'sentinel start'{C.RESET}\n")

    decoy_count = 0
    decoy_alive = 0
    tracker_file = DECEPTION_DIR / "config.json"
    if tracker_file.exists():
        try:
            _trk = json.loads(tracker_file.read_text())
            if isinstance(_trk, dict):
                decoy_count = len(_trk)
                decoy_alive = sum(1 for p in _trk if Path(p).exists())
        except Exception:
            pass
    if decoy_count == 0 and DECEPTION_DIR.exists():
        decoy_count = len([f for f in DECEPTION_DIR.rglob("*") if f.is_file()])
        decoy_alive = decoy_count
    if decoy_count:
        print(f"{C.BOLD}DECEPTION:{C.RESET} {decoy_alive}/{decoy_count} canaries alive")
    else:
        print(f"{C.BOLD}DECEPTION:{C.RESET} 0 artifacts — run: python3 sentinel.py deception")

    if blocked_count > 0:
        print(f"\n{C.BOLD}BLOCKED IPs ({blocked_count}){C.RESET}")
        for ip, info in list(blocked.items())[:10]:
            print(f"  {C.RED}🚫{C.RESET} {C.BOLD}{ip}{C.RESET} — {info.get('reason', '')} (until {str(info.get('block_until', ''))[:19]})")

    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")


def show_status(data, config, logger):
    devices = data.get("devices", {})
    total_scans = data.get("total_scans", 0)
    deception_active = config.get("deception", {}).get("active", True)

    fim_a = config.get("fim", {}).get("active", False)
    pm_a = config.get("process_monitor", {}).get("active", False)
    ssh_a = config.get("ssh_blocking", {}).get("active", False)
    om_a = config.get("outbound_monitor", {}).get("active", False)

    alert_count = 0
    if ALERT_LOG.exists():
        try:
            with open(ALERT_LOG) as f:
                alert_count = sum(1 for line in f if line.strip())
        except Exception:
            pass

    blocked_count = len(_load_blocklist().get("blocked", {}))

    print(f"""
{C.BOLD}{'=' * 50}
{C.BOLD}{C.CYAN}  SENTINEL v{__version__} STATUS{C.RESET}
{C.BOLD}{'─' * 50}
{C.BOLD}Host:{C.RESET}         {socket.gethostname()}
{C.BOLD}Local IP:{C.RESET}     {get_local_ip()}
{C.BOLD}MAC:{C.RESET}          {get_my_mac()}
{C.BOLD}Total Scans:{C.RESET}   {total_scans}
{C.BOLD}Devices:{C.RESET}       {C.BOLD}{len(devices)}{C.RESET}
{C.BOLD}Deception:{C.RESET}     {C.GREEN}{'ACTIVE' if deception_active else 'OFF'}{C.RESET}
{C.BOLD}Alerts:{C.RESET}        {C.BOLD}{alert_count}{C.RESET}
{C.BOLD}Blocked IPs:{C.RESET}    {C.BOLD}{blocked_count}{C.RESET}

{C.BOLD}LINE OF DEFENSE:{C.RESET}
  {C.BOLD}Filesystem Integrity:{C.RESET}  {C.GREEN}{'✓ ACTIVE' if fim_a else '✗ OFF'}{C.RESET}
  {C.BOLD}Process Monitor:{C.RESET}        {C.GREEN}{'✓ ACTIVE' if pm_a else '✗ OFF'}{C.RESET}
  {C.BOLD}SSH Brute Force Block:{C.RESET}  {C.GREEN}{'✓ ACTIVE' if ssh_a else '✗ OFF'}{C.RESET}
  {C.BOLD}Outbound Monitor:{C.RESET}       {C.GREEN}{'✓ ACTIVE' if om_a else '✗ OFF'}{C.RESET}
{C.BOLD}{'─' * 50}{C.RESET}
""")


# ════════════════════════════════════════════════════════════════════
# MAIN CLI
# ════════════════════════════════════════════════════════════════════


# ════════════════════════════════════════════════════════════════════
# CLIENT-READY: REALISTIC DECEPTION + CANARY WATCHER
# ════════════════════════════════════════════════════════════════════

def generate_realistic_decoy(dtype):
    def _rand(n):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
    if dtype == "aws":
        return f"[default]\naws_access_key_id = AKIA{_rand(16).upper()}\naws_secret_access_key = {_rand(40)}\nregion = us-east-1\n"
    if dtype == "env":
        return f"DB_HOST=db.internal.trintech.local\nDB_USER=admin\nDB_PASS={_rand(18)}\nAPI_KEY=sk_live_{_rand(32)}\nJWT_SECRET={_rand(48)}\n"
    if dtype == "ssh_key":
        return f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB{_rand(40)}\n-----END OPENSSH PRIVATE KEY-----\n"
    if dtype == "db":
        return f'{{\n  "host": "mysql.internal.trintech.local",\n  "port": 3306,\n  "user": "root",\n  "password": "{_rand(16)}",\n  "database": "production"\n}}\n'
    return f"admin:{_rand(12)}\nroot:{_rand(14)}\nbackup_user:{_rand(10)}\napi_service:sk-{_rand(24)}\n"


def deploy_deception(config, logger):
    """Deploy realistic decoys + canary beacons (client-ready)."""
    deception = config.get("deception", {})
    if not deception.get("active", True):
        logger.info("Deception disabled in config")
        return

    logger.info(f"{C.CYAN}[*]{C.RESET} Deploying realistic decoys + canary beacons...")
    home = Path.home()
    locations = [home / "Desktop", home / "Documents", home / "Downloads", home / ".config", Path("/tmp"), Path("/var/tmp")]
    specs = [
        ("aws_credentials", "aws", ".aws/credentials"),
        ("production.env", "env", ".env"),
        ("id_rsa_backup", "ssh_key", ".ssh/id_rsa_backup"),
        ("db_config.json", "db", "db_config.json"),
        ("passwords.txt", "creds", "passwords.txt"),
        ("api_keys.txt", "creds", "api_keys.txt"),
    ]
    DECEPTION_DIR.mkdir(parents=True, exist_ok=True)
    tracker = {}
    planted = 0
    for name, dtype, relpath in specs:
        content = generate_realistic_decoy(dtype)
        for base in locations:
            try:
                full = base / relpath
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text(content)
                full.chmod(0o600)
                canary_id = f"canary-{random.randint(100000,999999)}"
                central = config.get("agent", {}).get("central_url", "") or ""
                try:
                    content = embed_canary_beacon(content, canary_id, central)
                except Exception:
                    content = content + f"\n# SENTINEL-CANARY-ID: {canary_id}\n"
                tracker[str(full)] = {"type": dtype, "planted": datetime.now().isoformat(), "canary_id": canary_id, "size": len(content)}
                planted += 1
                logger.info(f"  {C.GREEN}✓{C.RESET} {full} [{canary_id}]")
            except Exception:
                pass
    with open(DECEPTION_DIR / "config.json", "w") as f:
        json.dump(tracker, f, indent=2)
    logger.info(f"{C.GREEN}✓{C.RESET} {planted} realistic decoys + canaries deployed")


def canary_watch(config, logger, interval=10):
    """Real-time watcher for decoy/canary files."""
    tracker_file = DECEPTION_DIR / "config.json"
    if not tracker_file.exists():
        logger.warning(f"{C.YELLOW}!{C.RESET} No canary tracker. Run deception first.")
        return
    with open(tracker_file) as f:
        tracker = json.load(f)
    baseline = {}
    for fpath, meta in tracker.items():
        try:
            st = os.stat(fpath)
            baseline[fpath] = {"mtime": st.st_mtime, "size": st.st_size, "canary_id": meta.get("canary_id")}
        except FileNotFoundError:
            baseline[fpath] = None
    logger.info(f"{C.CYAN}[*]{C.RESET} Canary watcher — monitoring {len(baseline)} decoys (Ctrl+C to stop)")
    try:
        while True:
            for fpath, base in list(baseline.items()):
                try:
                    st = os.stat(fpath)
                    current = {"mtime": st.st_mtime, "size": st.st_size}
                    if base is None:
                        logger.warning(f"{C.RED}⚠ CANARY REAPPEARED:{C.RESET} {fpath}")
                        send_alert("CANARY_REAPPEARED", {"path": fpath}, logger)
                        baseline[fpath] = current
                    elif current["mtime"] != base["mtime"] or current["size"] != base["size"]:
                        cid = base.get("canary_id", "unknown")
                        logger.warning(f"{C.RED}⚠ CANARY TRIGGERED:{C.RESET} {C.BOLD}{fpath}{C.RESET} [{cid}]")
                        send_alert("CANARY_TRIGGERED", {"path": fpath, "canary_id": cid}, logger)
                        baseline[fpath] = current
                except FileNotFoundError:
                    if base is not None:
                        logger.warning(f"{C.RED}⚠ CANARY DELETED:{C.RESET} {fpath}")
                        send_alert("CANARY_DELETED", {"path": fpath, "canary_id": base.get("canary_id")}, logger)
                        baseline[fpath] = None
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info(f"{C.GREEN}✓{C.RESET} Canary watcher stopped")


# ════════════════════════════════════════════════════════════════════
# CLIENT-READY: PDF REPORTS
# ════════════════════════════════════════════════════════════════════

def generate_pdf_report(config, logger, output_path=None):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        logger.error(f"{C.RED}✗ reportlab not installed. Run: pip install reportlab{C.RESET}")
        return None

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path.home() / f"Sentinel_Report_{ts}.pdf"

    devices = load_devices()
    alerts = []
    if ALERT_LOG.exists():
        with open(ALERT_LOG) as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except Exception:
                    pass
    alerts = alerts[-30:]

    doc = SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=20*mm, leftMargin=20*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleMain", fontSize=18, alignment=TA_CENTER, spaceAfter=6, textColor=colors.HexColor("#1a365d")))
    styles.add(ParagraphStyle(name="SubHead", fontSize=12, spaceBefore=12, spaceAfter=4, textColor=colors.HexColor("#2c5282")))
    styles.add(ParagraphStyle(name="Body", fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="Small", fontSize=8, textColor=colors.gray))

    story = []
    story.append(Paragraph("SENTINEL SECURITY REPORT", styles["TitleMain"]))
    story.append(Paragraph("TrinTech Digital Defense — Line of Defense Engine v2.1", styles["Small"]))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2c5282")))
    story.append(Spacer(1, 8))
    story.append(Paragraph("1. Executive Summary", styles["SubHead"]))
    host = socket.gethostname()
    ip = get_local_ip()
    device_count = len(devices.get("devices", {}))
    story.append(Paragraph(f"Host: <b>{host}</b> &nbsp; IP: <b>{ip}</b><br/>Devices: <b>{device_count}</b> &nbsp; Alerts: <b>{len(alerts)}</b><br/>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Body"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Network Devices", styles["SubHead"]))
    device_data = [["IP", "Hostname / MAC", "Ports", "Last Seen"]]
    for ip_addr, info in list(devices.get("devices", {}).items())[:25]:
        hostname = str(info.get("hostname", info.get("mac", "—")))[:22]
        ports = ", ".join(str(p) for p in info.get("ports", [])[:6]) or "—"
        last = str(devices.get("last_seen", {}).get(ip_addr, "—"))[:16]
        device_data.append([ip_addr, hostname, ports[:30], last])
    if len(device_data) > 1:
        t = Table(device_data, colWidths=[90, 120, 140, 90])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No devices recorded yet. Run <b>sentinel start</b>.", styles["Body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("3. Recent Alerts", styles["SubHead"]))
    if alerts:
        alert_data = [["Time", "Type", "Details"]]
        for a in reversed(alerts[-12:]):
            alert_data.append([a.get("timestamp", "")[:19], a.get("type", ""), str(a.get("details", ""))[:70]])
        t2 = Table(alert_data, colWidths=[110, 100, 270])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c53030")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No alerts recorded.", styles["Body"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("4. Recommendations", styles["SubHead"]))
    for r in ["Keep Sentinel in hunt mode for continuous monitoring.", "Review NEW_DEVICE and CANARY_TRIGGERED alerts immediately.", "Ensure SSH blocking remains enabled.", "Re-run deception after major system changes.", "Schedule weekly integrity baselines."]:
        story.append(Paragraph(f"• {r}", styles["Body"]))
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph("TrinTech Digital Defense  •  Confidential  •  Authorized use only", styles["Small"]))
    doc.build(story)
    logger.info(f"{C.GREEN}✓{C.RESET} PDF report written to {C.BOLD}{output_path}{C.RESET}")
    print(f"\n{C.GREEN}{C.BOLD}PDF Report ready:{C.RESET} {output_path}")
    return str(output_path)


# ════════════════════════════════════════════════════════════════════
# CLIENT-READY: MULTI-HOST AGENT (TOKEN AUTH)
# ════════════════════════════════════════════════════════════════════

def agent_collect_local():
    data = {"hostname": socket.gethostname(), "ip": get_local_ip(), "timestamp": datetime.now().isoformat(), "processes": [], "canaries": {}}
    try:
        result = run_cmd(["ps", "auxww", "--no-headers"], timeout=8)
        RS = [r"bash\s+-i", r"/dev/tcp/", r"nc\s+.*-e", r"python.*socket"]
        for line in result.strip().split("\n"):
            parts = line.split()
            if len(parts) < 11:
                continue
            cmd = " ".join(parts[10:])
            for pat in RS:
                if re.search(pat, cmd, re.I):
                    data["processes"].append({"pid": parts[1], "user": parts[0], "cmd": cmd[:120], "reason": "reverse_shell"})
                    break
    except Exception:
        pass
    tracker_file = DECEPTION_DIR / "config.json"
    if tracker_file.exists():
        try:
            with open(tracker_file) as f:
                tracker = json.load(f)
            for fpath, meta in tracker.items():
                try:
                    st = os.stat(fpath)
                    data["canaries"][fpath] = {"mtime": st.st_mtime, "size": st.st_size, "canary_id": meta.get("canary_id")}
                except FileNotFoundError:
                    data["canaries"][fpath] = {"status": "missing", "canary_id": meta.get("canary_id")}
        except Exception:
            pass
    return data


def agent_report_to_central(central_url, data, token=None):
    try:
        if token is None:
            token = load_config_safe().get("agent", {}).get("shared_token", "")
        payload = json.dumps(data).encode()
        req = urllib.request.Request(
            central_url.rstrip("/") + "/agent/report",
            data=payload,
            headers=tls_agent_headers(token or ""),
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def run_agent_mode(config, logger, central_url=None, interval=60):
    if not central_url:
        central_url = config.get("agent", {}).get("central_url", "")
    if not central_url:
        logger.error(f"{C.RED}✗ No central URL. Use: sentinel agent http://CENTRAL_IP:8743{C.RESET}")
        return
    logger.info(f"{C.CYAN}[*]{C.RESET} Agent mode → {C.BOLD}{central_url}{C.RESET} (interval {interval}s)")
    try:
        while True:
            data = agent_collect_local()
            token = config.get("agent", {}).get("shared_token", "")
            ok = agent_report_to_central(central_url, data, token=token)
            if ok:
                logger.info(f"{C.GREEN}✓{C.RESET} Report sent ({len(data.get('processes',[]))} susp procs, {len(data.get('canaries',{}))} canaries)")
            else:
                logger.warning(f"{C.YELLOW}!{C.RESET} Failed to reach central node")
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info(f"{C.GREEN}✓{C.RESET} Agent stopped")


class AgentHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/canary/beacon"):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            cid = (qs.get("id") or [""])[0]
            config = load_config_safe()
            meta = {"client": self.client_address[0], "path": self.path}
            try:
                handle_canary_beacon(cid, meta, config, send_alert=send_alert)
            except Exception:
                pass
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"recorded"}')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/agent/report":
            self.send_response(404)
            self.end_headers()
            return
        config = load_config_safe()
        expected = config.get("agent", {}).get("shared_token", "")
        received = self.headers.get("X-Sentinel-Token", "")
        if not expected or received != expected:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode())
            AGENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
            host = re.sub(r'[^a-zA-Z0-9_-]', '_', data.get("hostname", "unknown"))[:40]
            fname = AGENT_DATA_DIR / f"{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(fname, "w") as f:
                json.dump(data, f, indent=2)
            for p in data.get("processes", []):
                if p.get("reason") == "reverse_shell":
                    send_alert("AGENT_REVERSE_SHELL", {"agent": data.get("hostname"), "ip": data.get("ip"), "cmd": p.get("cmd")})
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except (BrokenPipeError, ConnectionResetError):
                pass
        except Exception as e:
            try:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(str(e).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass


def start_central_listener(logger, port=None):
    port = port or load_config_safe().get("agent", {}).get("port", AGENT_PORT)
    AGENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    server = socketserver.TCPServer(("0.0.0.0", port), AgentHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info(f"{C.GREEN}✓{C.RESET} Central agent listener on port {C.BOLD}{port}{C.RESET} (token auth required)")
    return server


# ════════════════════════════════════════════════════════════════════
# CLIENT-READY: HARDENING HELPERS
# ════════════════════════════════════════════════════════════════════

def harden_permissions(logger=None):
    for p in [SENTINEL_DIR, DATA_DIR, DECEPTION_DIR, INTEGRITY_DIR, CONFIG_FILE, ALERT_LOG]:
        try:
            p = Path(p)
            if not p.exists():
                continue
            os.chmod(p, 0o700 if p.is_dir() else 0o600)
        except Exception:
            pass
    if logger:
        logger.info(f"{C.GREEN}✓{C.RESET} Permissions hardened")


def self_integrity_check(logger=None):
    """Watch only the engine binary — config.json is expected to change."""
    critical = [Path(__file__).resolve()]
    current = {str(f): sha256_file(f) for f in critical if f.exists()}
    if not SELF_INTEGRITY_FILE.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(SELF_INTEGRITY_FILE, "w") as fh:
            json.dump(current, fh, indent=2)
        if logger:
            logger.info(f"{C.GREEN}\u2713{C.RESET} Self-integrity baseline created")
        return True
    try:
        with open(SELF_INTEGRITY_FILE) as fh:
            baseline = json.load(fh)
    except Exception:
        return False
    baseline = {k: v for k, v in baseline.items() if not k.endswith("config.json")}
    tampered = [fp for fp, h in current.items() if fp in baseline and baseline[fp] != h]
    if tampered:
        if logger:
            logger.warning(f"{C.RED}\u26a0 SELF-INTEGRITY VIOLATION:{C.RESET} {tampered}")
        send_alert("SELF_INTEGRITY_VIOLATION", {"files": tampered}, logger)
        return False
    try:
        with open(SELF_INTEGRITY_FILE, "w") as fh:
            json.dump(current, fh, indent=2)
    except Exception:
        pass
    if logger:
        logger.info(f"{C.GREEN}\u2713{C.RESET} Self-integrity check passed")
    return True




def rotate_logs(max_bytes=5_000_000, keep=5, logger=None):
    if not ALERT_LOG.exists() or ALERT_LOG.stat().st_size < max_bytes:
        return
    try:
        for i in range(keep, 0, -1):
            src_p = Path(f"{ALERT_LOG}.{i}") if i > 1 else ALERT_LOG
            dst_p = Path(f"{ALERT_LOG}.{i+1}")
            if src_p.exists():
                if i == keep:
                    src_p.unlink(missing_ok=True)
                else:
                    src_p.rename(dst_p)
        ALERT_LOG.write_text("")
        if logger:
            logger.info(f"{C.GREEN}✓{C.RESET} Rotated alerts.log")
    except Exception:
        pass


def uninstall_sentinel(logger=None):
    import shutil, subprocess
    print(f"\n{C.YELLOW}This will remove Sentinel data, services, and configuration.{C.RESET}")
    if input("Type YES to confirm uninstall: ").strip() != "YES":
        print("Cancelled.")
        return
    for svc in ["sentinel-central", "sentinel-agent"]:
        subprocess.run(["systemctl", "stop", svc], capture_output=True)
        subprocess.run(["systemctl", "disable", svc], capture_output=True)
        sf = Path(f"/etc/systemd/system/{svc}.service")
        if sf.exists():
            sf.unlink()
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    if SENTINEL_DIR.exists():
        shutil.rmtree(SENTINEL_DIR, ignore_errors=True)
        print(f"[+] Removed {SENTINEL_DIR}")
    lr = Path("/etc/logrotate.d/sentinel")
    if lr.exists():
        lr.unlink()
    print(f"{C.GREEN}Sentinel uninstalled.{C.RESET}")







def print_banner():
    """Simple SENTINEL banner."""
    line = "=" * 52
    print()
    print(f"{C.CYAN}{C.BOLD}{line}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  SENTINEL{C.RESET}")
    try:
        ver = __version__
    except Exception:
        ver = "2.5.0"
    print(f"{C.BOLD}  v{ver}{C.RESET}")
    print(f"{C.GRAY}  TrinTech Digital Defense{C.RESET}")
    print(f"{C.GRAY}  Active Deception | Persistence Hunting | Line of Defense{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{line}{C.RESET}")
    print()


def interactive_menu(config=None, logger=None):
    """Numbered menu — option 1 = start + continuous hunt."""
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    eng = _Path(__file__).resolve()

    def run(*args):
        try:
            subprocess.call([_sys.executable, str(eng), *args])
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}Stopped.{C.RESET}")

    def run_continuous_defense():
        print(f"\n  {C.CYAN}{C.BOLD}[*] Full start (scan + decoys + checks)...{C.RESET}\n")
        run("start")
        print(f"\n  {C.GREEN}{C.BOLD}[*] Continuous protection ON — hunt loop{C.RESET}")
        print(f"  {C.GRAY}Ctrl+C to stop and return to menu{C.RESET}\n")
        run("hunt")

    main_items = [
        ("1",  "START continuous protection (scan once + stay hunting)", ("__continuous__",)),
        ("2",  "Quick network scan (one-shot)", ("scan",)),
        ("3",  "Hunt only (continuous) — Ctrl+C to stop", ("hunt",)),
        ("4",  "Deploy deception / canary traps", ("deception",)),
        ("5",  "Integrity baseline (FIM)", ("integrity",)),
        ("6",  "Scan suspicious processes", ("processes",)),
        ("7",  "Show full report", ("report",)),
        ("8",  "Phase 4 tools (baseline, Caribbean, playbooks...)", ("__phase4__",)),
        ("9",  "System info", ("info",)),
        ("10", "View alerts", ("alerts",)),
        ("11", "Hardening audit", ("hardening",)),
        ("12", "Status", ("status",)),
        ("13", "Always-on service (systemd)", ("service-install",)),
        ("14", "Service status", ("service-status",)),
        ("15", "Schedule WhatsApp digest (daily cron)", ("digest-cron",)),
        ("0",  "Exit", ("__exit__",)),
    ]

    p4_items = [
        ("1", "Phase 4 self-check", ("phase4",)),
        ("2", "Build behavioral baseline", ("baseline",)),
        ("3", "Check vs baseline (anomalies)", ("baseline", "check")),
        ("4", "Caribbean / T&T threat pack", ("caribbean",)),
        ("5", "List response playbooks", ("playbook",)),
        ("6", "Export evidence pack (24h)", ("evidence", "--hours", "24")),
        ("7", "Offline alert queue", ("offline",)),
        ("0", "Back to main menu", ("__back__",)),
    ]

    def show(items, title):
        print(f"\n{C.CYAN}{C.BOLD}  {title}{C.RESET}")
        print("  " + "-" * 54)
        for num, label, _ in items:
            print(f"  {C.BOLD}{num:>2}{C.RESET}  {label}")
        print("  " + "-" * 54)

    def loop(items, title):
        while True:
            try:
                print_banner()
            except Exception:
                print("\n  SENTINEL — Interactive Menu\n")
            show(items, title)
            try:
                pick = input(f"\n  {C.BOLD}Select:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return "exit"
            mapping = {n: args for n, _, args in items}
            if pick not in mapping:
                print(f"  {C.RED}Invalid choice — try again{C.RESET}")
                continue
            args = mapping[pick]
            if args[0] == "__exit__":
                print(f"\n  {C.GREEN}Goodbye.{C.RESET}\n")
                return "exit"
            if args[0] == "__back__":
                return "back"
            if args[0] == "__phase4__":
                loop(p4_items, "PHASE 4 — Advanced tools")
                continue
            if args[0] == "__continuous__":
                run_continuous_defense()
            else:
                run(*args)
            try:
                input(f"\n  {C.GRAY}Press Enter to continue...{C.RESET}")
            except EOFError:
                pass

    loop(main_items, "MAIN MENU")



def main():
    # fix_ui: open numbered menu when no command given
    if len(sys.argv) < 2:
        interactive_menu()
        return
    # fix_ui: open numbered menu when no command given
    if len(sys.argv) < 2:
        banner()
        print(f"{C.BOLD}{C.BLUE}USAGE:{C.RESET}")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}start[ -v]{C.RESET}          Full scan + deception + Line of Defense")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}scan[ -v]{C.RESET}           Quick network scan")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}report{C.RESET}              Show full report")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}status{C.RESET}              Show current status")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}config[ -v]{C.RESET}        Initialize/edit config")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}alerts{C.RESET}               Show recent alerts")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}deception{C.RESET}           Deploy deception artifacts")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}hunt[ -v]{C.RESET}              Start persistence hunting")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}info{C.RESET}                 System info")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}clean{C.RESET}                 Reset all tracking data")
        print()
        print(f"{C.BOLD}{C.CYAN}LINE OF DEFENSE:{C.RESET}")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}integrity{C.RESET}         Generate integrity baseline (or check if --check)")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}integrity --check{C.RESET}  Check integrity only")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}watch[ -v]{C.RESET}             Start real-time filesystem watcher")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}processes{C.RESET}            Scan for suspicious processes")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}outbound{C.RESET}              Show outbound connections")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}blocklist{C.RESET}             Show blocked IPs")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}unblock <ip>{C.RESET}         Unblock an IP")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}users{C.RESET}                 Show user accounts & sudo")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}cron{C.RESET}                   Check cron integrity")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}hardening{C.RESET}              Run system hardening audit")
        print()
        print(f"{C.BOLD}{C.CYAN}PHASE 1:{C.RESET}")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}onboard --client NAME{C.RESET}  Client onboarding")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}quiet on|off{C.RESET}           Quiet mode")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}phase1{C.RESET}                 Phase 1 self-check")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}quarantine --status{C.RESET}   Quarantine evidence")
        print()
        sys.exit(0)

    command = sys.argv[1]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    args = sys.argv[2:]
    logger = setup_logging(verbose)
    config = init_config(logger)
    harden_permissions(logger)
    self_integrity_check(logger)
    rotate_logs(logger=logger)
    banner()

    if command == "start":
        data = load_devices()
        scan_network(config, logger, data)
        deploy_deception(config, logger)
        persistence_hunt(config, logger)
        generate_report(data, config, logger)

    elif command == "scan":
        data = load_devices()
        scan_network(config, logger, data)
        generate_report(data, config, logger)

    elif command == "report":
        data = load_devices()
        generate_report(data, config, logger)

    elif command == "status":
        data = load_devices()
        show_status(data, config, logger)

    elif command == "deception":
        data = load_devices()
        deploy_deception(config, logger)
        generate_report(data, config, logger)

    elif command == "hunt":
        data = load_devices()
        logger.info(f"{C.CYAN}[*]{C.RESET} Persistence hunting — Ctrl+C to stop")
        interval = config.get("persistence", {}).get("monitor_interval", 60)
        try:
            while True:
                # --- Sentinel hooks (auto) ---
                try:
                    from modules.phase5 import heartbeat_from_hunt
                    heartbeat_from_hunt()
                except Exception:
                    pass
                try:
                    from modules.deadman import emit_heartbeat as _dm_emit, check_fleet as _dm_fleet
                    _dm_emit("hunt")
                    _dm_fleet()
                except Exception:
                    pass
                try:
                    from modules.usb_watch import check as _usb_check
                    _usb_check()
                except Exception:
                    pass
                try:
                    from modules.lateral import check as _lat_check
                    _lat_check()
                except Exception:
                    pass
                try:
                    from modules.dns_watch import check as _dns_check
                    _dns_check()
                except Exception:
                    pass
                try:
                    from modules.device_radar import check as _radar_check
                    _radar_check()
                except Exception:
                    pass
                try:
                    from modules.ransomware_tripwire import check as _tw_check
                    _tw_check()
                except Exception:
                    pass
                try:
                    from modules.honeyauth import check as _honey_check
                    _honey_check()
                except Exception:
                    pass
                # --- end hooks ---
                try:
                    persistence_hunt(config, logger)
                except Exception as _ph_err:
                    logger.warning(f"! persistence_hunt error: {_ph_err}")
                time.sleep(max(10, int(interval) if interval else 60))
        except KeyboardInterrupt:
            logger.info(f"{C.GREEN}✓{C.RESET} Persistence hunting stopped")

    elif command == "config":
        if verbose:
            print(f"{C.BOLD}Config:{C.RESET} {C.BOLD}{CONFIG_FILE}{C.RESET}")
            print(f"\n{C.BOLD}Contents:{C.RESET}")
            with open(CONFIG_FILE) as f:
                print(f.read())
        else:
            logger.info(f"{C.BOLD}Config:{C.RESET} {C.BOLD}{CONFIG_FILE}{C.RESET}")
            logger.info(f"Run {C.BOLD}sentinel config -v{C.RESET} to view")

    elif command == "alerts":
        if os.path.exists(str(ALERT_LOG)):
            with open(ALERT_LOG) as f:
                alerts = [json.loads(line) for line in f if line.strip()]
            if alerts:
                print(f"\n{C.BOLD}{C.RED}RECENT ALERTS ({len(alerts)}){C.RESET}")
                print(f"{'─' * 60}")
                for alert in alerts[-50:]:
                    at = alert.get("type", "")
                    severity = C.RED if at in ("NEW_DEVICE", "DECOY_MODIFIED", "FIM_MODIFIED",
                                                "SUSPICIOUS_PROCESS", "IP_BLOCKED", "FIM_DELETED",
                                                "LOG_TAMPERING", "OUTBOUND_SUSPICIOUS_PORT",
                                                "SECURITY_REGRESSION") else C.YELLOW
                    if at == "AUTH_FAILURE":
                        severity = C.YELLOW
                    print(f"  {severity}●{C.RESET} [{alert['timestamp'][:19]}] {C.BOLD}{at}{C.RESET}")
                print(f"\n{C.BOLD}Log:{C.RESET} {C.BOLD}{ALERT_LOG}{C.RESET} | {C.BOLD}Follow:{C.RESET} {C.BOLD}tail -f {ALERT_LOG}{C.RESET}")
            else:
                print(f"\n{C.GREEN}✓ No alerts.{C.RESET}")
        else:
            print(f"\n{C.GREEN}✓ No alerts yet. Run 'sentinel start' first.{C.RESET}")

    elif command == "clean":
        for fpath in [DEVICE_DB, ALERT_LOG, FIM_BASELINE, CRON_BASELINE, SSH_BLOCKLIST_FILE, USER_BASELINE, SUID_BASELINE]:
            if fpath.exists():
                fpath.unlink()
                logger.info(f"{C.GREEN}✓{C.RESET} Cleared {C.BOLD}{fpath}{C.RESET}")
        print(f"{C.GREEN}{C.BOLD}All tracking data reset.{C.RESET} Run 'sentinel start' to begin fresh.")

    elif command == "info":
        devices = load_devices()
        total_scans = devices.get("total_scans", 0)
        device_count = len(devices.get("devices", {}))

        print(f"""

{C.BOLD}{C.CYAN}SENTINEL SYSTEM INFO{C.RESET}
{C.BOLD}{'─' * 50}{C.RESET}
  {C.BOLD}Version:{C.RESET}      {__version__}
  {C.BOLD}Author:{C.RESET}      {__author__}
  {C.BOLD}Host:{C.RESET}        {socket.gethostname()}
  {C.BOLD}Local IP:{C.RESET}    {get_local_ip()}
  {C.BOLD}MAC:{C.RESET}         {get_my_mac()}
  {C.BOLD}Data Dir:{C.RESET}    {DATA_DIR}
  {C.BOLD}Config:{C.RESET}      {CONFIG_FILE}
  {C.BOLD}Total Scans:{C.RESET} {total_scans}
  {C.BOLD}Devices:{C.RESET}     {device_count}

  {C.BOLD}OS:{C.RESET}           {run_cmd(['uname', '-a'], timeout=5).strip()}

{C.BOLD}LINE OF DEFENSE:{C.RESET}
  {C.BOLD}FIM:{C.RESET}         {C.GREEN}{'✓' if FIM_BASELINE.exists() else '✗'} Baseline: {len(json.load(open(FIM_BASELINE))) if FIM_BASELINE.exists() else 0} files
  {C.BOLD}Processes:{C.RESET}   {C.GREEN}✓ Active{C.RESET}
  {C.BOLD}SSH Block:{C.RESET}    {C.GREEN}{'✓' if SSH_BLOCKLIST_FILE.exists() else '✗'} {len(_load_blocklist().get('blocked', {}))} IPs blocked
  {C.BOLD}Outbound:{C.RESET}     {C.GREEN}✓ Active{C.RESET}
  {C.BOLD}Users:{C.RESET}        {C.GREEN}✓ Active{C.RESET}
  {C.BOLD}Cron:{C.RESET}        {C.GREEN}{'✓' if CRON_BASELINE.exists() else '✗'} Baseline active
  {C.BOLD}Hardening:{C.RESET}  {C.GREEN}✓ Active{C.RESET}
{C.BOLD}{'─' * 50}{C.RESET}
""")

    # ── Line of Defense commands ──
    elif command == "integrity":

        try:
            from modules.drift import compute_score
            compute_score([])
        except Exception:
            pass

        if "--check" in args:
            logger.info(f"{C.CYAN}[*]{C.RESET} Checking integrity against baseline...")
            fim_check(config, logger)
        else:
            logger.info(f"{C.CYAN}[*]{C.RESET} Generating file integrity baseline...")
            fim_build_baseline(config, logger)

    elif command == "watch":
        fim_watch(config, logger)

    elif command == "processes":
        logger.info(f"{C.CYAN}[*]{C.RESET} Scanning processes...")
        suspicious = process_scan(config, logger)
        if suspicious:
            print(f"\n{C.BOLD}{C.RED}SUSPICIOUS PROCESSES ({len(suspicious)}){C.RESET}")
            for s in suspicious:
                print(f"  {C.RED}⚠{C.RESET} PID={s['pid']} User={s['user']} {s['command'][:60]}")

    elif command == "outbound":
        logger.info(f"{C.CYAN}[*]{C.RESET} Scanning outbound connections...")
        outbound_scan(config, logger)

    elif command == "blocklist":
        blocklist = _load_blocklist()
        blocked = blocklist.get("blocked", {})
        if blocked:
            print(f"\n{C.BOLD}{C.RED}BLOCKED IPs ({len(blocked)}){C.RESET}")
            print(f"{'─' * 60}")
            for ip, info in sorted(blocked.items()):
                print(f"  {C.RED}🚫{C.RESET} {C.BOLD}{ip}{C.RESET} — {info.get('reason', '')}")
                print(f"     Blocked: {info.get('blocked_at', 'N/A')} | Until: {info.get('block_until', 'N/A')}")
        else:
            print(f"\n{C.GREEN}✓ No IPs blocked.{C.RESET}")

    elif command == "unblock":
        if args:
            blocklist = _load_blocklist()
            ip = args[0]
            if ip in blocklist.get("blocked", {}):
                del blocklist["blocked"][ip]
                _save_blocklist(blocklist)
                run_cmd(f"iptables -D INPUT -s {ip} -j DROP", timeout=5)
                logger.info(f"{C.GREEN}✓{C.RESET} {C.BOLD}{ip}{C.RESET} unblocked")
                print(f"{C.GREEN}{C.BOLD}✓ {ip} unblocked.{C.RESET}")
            else:
                logger.warning(f"{C.YELLOW}!{C.RESET} {C.BOLD}{ip}{C.RESET} not in blocklist")
        else:
            logger.error(f"{C.RED}✗ Specify an IP: {C.BOLD}sentinel unblock <IP>{C.RESET}")

    elif command == "users":
        logger.info(f"{C.CYAN}[*]{C.RESET} Checking user accounts...")
        print(f"\n{C.BOLD}CURRENT USERS (UID >= 1000){C.RESET}")
        print(f"{'─' * 60}")
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and int(parts[2]) >= 1000 and parts[0] != "nobody":
                        print(f"  {C.BOLD}{parts[0]}{C.RESET} (UID:{parts[2]}) Home:{parts[5]} Shell:{parts[6]}")
        except Exception:
            pass

    elif command == "cron":
        logger.info(f"{C.CYAN}[*]{C.RESET} Checking cron integrity...")
        cron_monitor_check(config, logger)
        try:
            cr = run_cmd(["crontab", "-l"], timeout=5)
            if cr.strip():
                print(f"\n{C.BOLD}ROOT CRONTAB:{C.RESET}")
                for line in cr.strip().split("\n"):
                    if line.strip() and not line.startswith("#"):
                        print(f"  {C.BOLD}{line[:80]}{C.RESET}")
        except Exception:
            pass

    elif command == "hardening":
        logger.info(f"{C.CYAN}[*]{C.RESET} Running system hardening audit...")
        result = hardening_audit(config, logger)
        if result and result.get("score"):
            score = result["score"]
            print(f"""

{C.BOLD}{'=' * 60}
{C.BOLD}{C.CYAN}  HARDENING AUDIT{C.RESET}
{C.BOLD}{'=' * 60}
{C.BOLD}Score:{C.RESET}       {C.BOLD}{C.RED if score < 50 else C.YELLOW if score < 70 else C.GREEN}{score}/100{C.RESET}
{C.BOLD}Issues:{C.RESET}      {result['issue_count']}
{C.BOLD}{'=' * 60}{C.RESET}
""")
            if result.get("issues"):
                print(f"{C.BOLD}ISSUES:{C.RESET}")
                for issue in result["issues"]:
                    sev = C.RED if issue["severity"] == "critical" else C.YELLOW
                    print(f"  {sev}●{C.RESET} [{issue['severity'].upper()}] {issue['issue']}")

    elif command == "canary":
        canary_watch(config, logger)
    elif command in ("pdf", "report-pdf"):
        generate_pdf_report(config, logger)
    elif command == "agent":
        url = args[0] if args else None
        run_agent_mode(config, logger, central_url=url)
    elif command == "central":
        start_central_listener(logger)
        logger.info(f"{C.CYAN}[*]{C.RESET} Central mode — listening for agents + local hunt")
        interval = config.get("persistence", {}).get("monitor_interval", 60)
        try:
            while True:
                # --- Sentinel hooks (auto) ---
                try:
                    from modules.phase5 import heartbeat_from_hunt
                    heartbeat_from_hunt()
                except Exception:
                    pass
                try:
                    from modules.deadman import emit_heartbeat as _dm_emit, check_fleet as _dm_fleet
                    _dm_emit("central")
                    _dm_fleet()
                except Exception:
                    pass
                # --- end hooks ---
                try:
                    persistence_hunt(config, logger)
                except Exception as _ph_err:
                    logger.warning(f"! persistence_hunt error: {_ph_err}")
                time.sleep(max(10, int(interval) if interval else 60))
        except KeyboardInterrupt:
            logger.info(f"{C.GREEN}✓{C.RESET} Central mode stopped")

    elif command == "onboard":
        # sentinel onboard --client "Name" [--subnets 192.168.1.0/24]
        client = "client"
        subnets = None
        if "--client" in args:
            i = args.index("--client")
            if i + 1 < len(args):
                client = args[i + 1]
        elif args and not args[0].startswith("-"):
            client = args[0]
        if "--subnets" in args:
            i = args.index("--subnets")
            if i + 1 < len(args):
                subnets = [s.strip() for s in args[i + 1].split(",") if s.strip()]
        if client_onboard:
            summary = client_onboard(
                config, client, subnets=subnets, logger=logger,
                deploy_deception=deploy_deception, fim_build_baseline=fim_build_baseline,
                config_file=CONFIG_FILE,
            )
            print(f"\n{C.GREEN}{C.BOLD}Client onboarded:{C.RESET} {summary.get('client')}")
            print(f"  Token:  {summary.get('shared_token')}")
            print(f"  Agent:  {summary.get('agent_install')}")
            print(f"  {summary.get('note')}")
        else:
            logger.error("Phase 1 onboard module not available")

    elif command == "quiet":
        mode = (args[0] if args else "").lower()
        config.setdefault("quiet", {})["enabled"] = mode in ("on", "1", "true", "enable")
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        state = "ON" if config["quiet"]["enabled"] else "OFF"
        logger.info(f"{C.GREEN}✓{C.RESET} Quiet mode {C.BOLD}{state}{C.RESET}")

    elif command == "phase1":
        info = phase1_self_check(config)
        print(f"\n{C.BOLD}{C.CYAN}PHASE 1 SELF-CHECK{C.RESET}")
        for k, v in info.items():
            print(f"  {k}: {v}")

    elif command == "quarantine":
        qdir = DATA_DIR / "quarantine"
        if args and args[0] == "--status":
            files = list(qdir.glob("*.json")) if qdir.exists() else []
            print(f"\n{C.BOLD}Quarantine evidence files: {len(files)}{C.RESET}")
            for f in sorted(files)[-20:]:
                print(f"  {f.name}")
        else:
            qc = config.get("quarantine", {})
            print(f"enabled={qc.get('enabled')} block_ip={qc.get('block_ip')} kill_process={qc.get('kill_process')}")
            print("Use: sentinel quarantine --status")


    elif command in ("phase5", "p5"):
        try:
            from modules.phase5 import phase5_self_check, heartbeat_write, ensure_hygiene_defaults, ensure_whatsapp_defaults
            ensure_hygiene_defaults()
            ensure_whatsapp_defaults()
            heartbeat_write({"source": "phase5"})
            print(phase5_self_check())
        except Exception as e:
            print("[!] phase5:", e)
    elif command == "autosubnet":
        try:
            from modules.phase5 import auto_subnet_apply
            print(auto_subnet_apply())
        except Exception as e:
            print("[!] autosubnet:", e)
    elif command == "heartbeat":
        try:
            from modules.phase5 import heartbeat_write, heartbeat_status
            print(heartbeat_write({"source": "cli"}))
            print(heartbeat_status())
        except Exception as e:
            print("[!] heartbeat:", e)
    elif command == "digest":
        try:
            from modules.phase5 import alert_digest
            hours = 24
            if "--hours" in args:
                i = args.index("--hours")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(alert_digest(hours))
        except Exception as e:
            print("[!] digest:", e)
    elif command in ("whatsapp-digest", "wa-digest", "digest-send"):
        try:
            from modules.phase5 import whatsapp_digest
            hours = 24
            force = "--force" in args
            if "--hours" in args:
                i = args.index("--hours")
                if i + 1 < len(args):
                    hours = int(args[i + 1])
            print(whatsapp_digest(hours=hours, force=force))
        except Exception as e:
            print("[!] whatsapp-digest:", e)
    elif command in ("hygiene", "alert-hygiene"):
        try:
            from modules.phase5 import hygiene_status, hygiene_reset, ensure_hygiene_defaults
            ensure_hygiene_defaults()
            if "--reset" in args or (args and args[0] == "reset"):
                print(hygiene_reset())
            print(hygiene_status())
        except Exception as e:
            print("[!] hygiene:", e)


    elif command in ("service-install", "install-service"):
        try:
            from modules.phase5 import service_install
            print(service_install())
        except Exception:
            try:
                import os, textwrap
                unit = textwrap.dedent("""
                [Unit]
                Description=SENTINEL persistence hunt
                After=network.target
                [Service]
                Type=simple
                WorkingDirectory=/tmp/SentinelP56
                ExecStart=/usr/bin/python3 /tmp/SentinelP56/sentinel.py hunt
                Restart=always
                RestartSec=10
                [Install]
                WantedBy=multi-user.target
                """).strip() + "\n"
                path = Path("/etc/systemd/system/sentinel-hunt.service")
                path.write_text(unit)
                os.system("systemctl daemon-reload")
                os.system("systemctl enable --now sentinel-hunt.service")
                print("[+] service sentinel-hunt installed/started (fallback)")
            except Exception as e2:
                print("[!] service-install:", e2)
    elif command in ("service-status",):
        try:
            import subprocess
            r = subprocess.run(["systemctl", "is-active", "sentinel-hunt"], capture_output=True, text=True)
            print(r.stdout.strip() or r.stderr.strip() or "unknown")
        except Exception as e:
            print("[!] service-status:", e)
    elif command in ("digest-cron", "schedule-digest"):
        try:
            from modules.phase5 import install_digest_cron
            sch = "weekly" if "--weekly" in args else "daily"
            print(install_digest_cron(sch))
        except Exception as e:
            print("[!] digest-cron:", e)

    
    elif command == "baseline":
        config = ensure_phase4_defaults(config)
        if args and args[0] in ("check", "scan"):
            result = baseline_check(config)
            print(result)
        else:
            print(baseline_build(config))
    elif command == "caribbean":
        result = caribbean_scan(ensure_phase4_defaults(config))
        print(result)
    elif command == "playbook":
        if not args:
            for p in playbook_list():
                print(p)
        else:
            pb = playbook_get(args[0])
            print(pb.get("title"), pb.get("severity"))
            for s in pb.get("steps") or []:
                print(s)
    elif command == "evidence":
        hours = 24
        if "--hours" in args:
            i = args.index("--hours")
            if i+1 < len(args): hours = int(args[i+1])
        print(evidence_pack(hours=hours))
    elif command == "offline":
        if args and args[0] == "flush":
            print(offline_flush())
        else:
            print(offline_status())
    elif command == "phase4":
        config = ensure_phase4_defaults(config)
        print(phase4_self_check(config))
    
    elif command in ("phase7", "p7"):
        try:
            from modules.phase7 import phase7_self_check
            print(phase7_self_check())
        except Exception as e:
            print("[!] phase7:", e)
    elif command in ("central", "central-status"):
        try:
            from modules.phase7 import central_serve
            host, port = "0.0.0.0", 8790
            if "--host" in args:
                host = args[args.index("--host") + 1]
            if "--port" in args:
                port = int(args[args.index("--port") + 1])
            central_serve(host, port)
        except Exception as e:
            print("[!] central:", e)
    elif command in ("agents", "agents-list"):
        try:
            from modules.phase7 import agents_list
            print(agents_list())
        except Exception as e:
            print("[!] agents:", e)
    elif command in ("agent-report", "report-in"):
        try:
            from modules.phase7 import agent_self_report
            url = None
            if "--central" in args:
                url = args[args.index("--central") + 1]
            print(agent_self_report(url))
        except Exception as e:
            print("[!] agent-report:", e)
    elif command in ("quiet", "quiet-hours"):
        try:
            from modules.phase7 import quiet_status, quiet_set
            if "--on" in args:
                print(quiet_set(enabled=True))
            elif "--off" in args:
                print(quiet_set(enabled=False))
            else:
                start = end = None
                if "--start" in args:
                    start = args[args.index("--start") + 1]
                if "--end" in args:
                    end = args[args.index("--end") + 1]
                if start or end:
                    print(quiet_set(start=start, end=end))
                else:
                    print(quiet_status())
        except Exception as e:
            print("[!] quiet:", e)
    elif command in ("release", "version"):
        try:
            from modules.phase7 import release_info
            print(release_info())
        except Exception as e:
            print("[!] release:", e)
    elif command in ("win-agent", "windows-agent"):
        try:
            from modules.phase7 import write_windows_agent
            print(write_windows_agent())
        except Exception as e:
            print("[!] win-agent:", e)

    
    elif command in ("doctor", "health", "check"):
        try:
            from modules.doctor import run_doctor
            run_doctor(verbose=True)
        except Exception as e:
            print("[!] doctor:", e)

    
    elif command in ("drift", "drift-report"):
        try:
            from modules.drift import print_report
            print_report()
        except Exception as e:
            print("[!] drift:", e)
    elif command in ("deadman", "dead-man", "heartbeat-check"):
        try:
            from modules.deadman import print_status, ensure_defaults
            ensure_defaults()
            print_status()
        except Exception as e:
            print("[!] deadman:", e)

    
    elif command in ("drift-pdf", "report-drift"):
        try:
            from modules.drift_pdf import generate_drift_pdf
            print(generate_drift_pdf())
        except Exception as e:
            print("[!] drift-pdf:", e)
    elif command in ("attack", "att&ck", "mitre"):
        try:
            from modules.attack_map import summarize_techniques, print_map_sample
            print_map_sample()
            from pathlib import Path as P
            alerts = []
            ap = P.home() / ".sentinel/data/alerts.log"
            if ap.exists():
                for line in ap.read_text(errors="ignore").splitlines()[-50:]:
                    alerts.append({"reason": line[:80], "type": "alert"})
            print({"techniques_observed": summarize_techniques(alerts)})
        except Exception as e:
            print("[!] attack:", e)
    elif command in ("bot", "telegram-bot"):
        try:
            from modules.bot import run_bot_loop, ensure_bot_defaults, bot_config
            ensure_bot_defaults()
            cfg = bot_config()
            print("telegram config:", {k: cfg[k] for k in ("enabled", "chat_id")})
            run_bot_loop()
        except Exception as e:
            print("[!] bot:", e)
    elif command in ("bot-test",):
        try:
            from modules.bot import handle_command, ensure_bot_defaults
            ensure_bot_defaults()
            print(handle_command("STATUS"))
        except Exception as e:
            print("[!] bot-test:", e)
    elif command in ("usb", "usb-watch"):
        try:
            from modules.usb_watch import check
            print(check())
        except Exception as e:
            print("[!] usb:", e)
    elif command in ("lateral",):
        try:
            from modules.lateral import check
            print(check())
        except Exception as e:
            print("[!] lateral:", e)
    elif command in ("dns", "dns-watch"):
        try:
            from modules.dns_watch import check
            print(check())
        except Exception as e:
            print("[!] dns:", e)
    elif command in ("persistence-baseline",):
        try:
            from modules.persistence_hunt import create_baseline
            print(create_baseline())
        except Exception as e:
            print("[!] persistence-baseline:", e)
    elif command in ("persistence", "persistence-check"):
        try:
            from modules.persistence_hunt import check
            print(check())
        except Exception as e:
            print("[!] persistence:", e)
    elif command in ("detect", "tier2"):
        try:
            from modules.usb_watch import check as usb_check
            from modules.lateral import check as lat_check
            from modules.dns_watch import check as dns_check
            from modules.persistence_hunt import check as per_check
            from modules.attack_map import tag_alert
            bundle = {
                "usb": usb_check(),
                "lateral": lat_check(),
                "dns": dns_check(),
                "persistence": per_check(),
            }
            for key in bundle:
                evs = bundle[key].get("events") or []
                bundle[key]["events"] = [tag_alert(e) for e in evs[:10]]
            print(bundle)
        except Exception as e:
            print("[!] detect:", e)

    
    elif command in ("portal", "webview"):
        try:
            from modules.webview import start_portal, ensure_portal_token
            tok = ensure_portal_token()
            print("Portal token:", tok)
            start_portal()
        except Exception as e:
            print("[!] portal:", e)
    elif command in ("portal-url",):
        try:
            from modules.webview import ensure_portal_token, _cfg
            tok = ensure_portal_token()
            port = (_cfg().get("portal") or {}).get("port", 8791)
            print(f"http://127.0.0.1:{port}/?token={tok}")
        except Exception as e:
            print("[!] portal-url:", e)
    elif command in ("honey", "honeyauth"):
        try:
            from modules.honeyauth import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] honey:", e)
    elif command in ("crypto-status",):
        try:
            from modules.crypto_store import status, ensure_key
            ensure_key()
            print(status())
        except Exception as e:
            print("[!] crypto:", e)
    elif command in ("encrypt-store",):
        try:
            from modules.crypto_store import write_encrypted_json, read_encrypted_json
            from pathlib import Path as P
            p = P.home() / ".sentinel/data/secure_sample.json.enc"
            write_encrypted_json(p, {"ok": True, "note": "sentinel encrypted store"})
            print({"wrote": str(p), "read_back": read_encrypted_json(p)})
        except Exception as e:
            print("[!] encrypt-store:", e)
    elif command in ("protect-pdf",):
        try:
            import sys as _sys
            from pathlib import Path as P
            from modules.crypto_store import protect_pdf
            args = _sys.argv[2:]
            src = P(args[0]) if args else P.home() / "Sentinel_Report.pdf"
            pw = args[1] if len(args) > 1 else "TrinTech"
            print(protect_pdf(src, pw))
        except Exception as e:
            print("[!] protect-pdf:", e)
    elif command in ("suppress", "suppressions"):
        try:
            from modules.suppressions import print_rules
            print_rules()
        except Exception as e:
            print("[!] suppress:", e)
    elif command in ("suppress-add",):
        try:
            import sys as _sys
            from modules.suppressions import add_suppression
            a = _sys.argv[2:]
            if len(a) < 2:
                print("Usage: sentinel suppress-add <detection_type> <pattern>")
            else:
                print(add_suppression(a[0], a[1], note="manual"))
        except Exception as e:
            print("[!] suppress-add:", e)
    elif command in ("suppress-del",):
        try:
            import sys as _sys
            from modules.suppressions import remove_rule
            rid = _sys.argv[2] if len(_sys.argv) > 2 else ""
            print({"removed": remove_rule(rid), "id": rid})
        except Exception as e:
            print("[!] suppress-del:", e)

    
    elif command in ("rules", "rules-check"):
        try:
            from modules.rules_engine import load_rules, check_events, ensure_default_rules
            ensure_default_rules()
            print({"rules": len(load_rules()), "sample": check_events([{"command": "bash -i", "reason": "reverse_shell"}])})
        except Exception as e:
            print("[!] rules:", e)
    elif command in ("devices", "radar", "new-devices"):
        try:
            from modules.device_radar import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] radar:", e)
    elif command in ("device-approve",):
        try:
            import sys as _sys
            from modules.device_radar import approve
            key = _sys.argv[2] if len(_sys.argv) > 2 else ""
            print(approve(key))
        except Exception as e:
            print("[!] device-approve:", e)
    elif command in ("tripwire-deploy",):
        try:
            from modules.ransomware_tripwire import deploy
            print(deploy())
        except Exception as e:
            print("[!] tripwire-deploy:", e)
    elif command in ("tripwire", "ransomware"):
        try:
            from modules.ransomware_tripwire import check
            from modules.attack_map import tag_alert
            from modules.suppressions import filter_events
            r = check()
            r["events"] = [tag_alert(e) for e in filter_events(r.get("events") or [])]
            print(r)
        except Exception as e:
            print("[!] tripwire:", e)
    elif command in ("external", "posture"):
        try:
            import sys as _sys
            from modules.external_posture import check
            domain = _sys.argv[2] if len(_sys.argv) > 2 else None
            print(check(domain=domain))
        except Exception as e:
            print("[!] external:", e)
    elif command in ("fleet", "fleet-console"):
        try:
            from modules.fleet_console import print_console, write_html
            print_console()
            print("HTML:", write_html())
        except Exception as e:
            print("[!] fleet:", e)
    elif command in ("bonus-test", "test-all"):
        try:
            print("=== BONUS SELF-TEST ===")
            from modules.rules_engine import ensure_default_rules, load_rules, check_events
            ensure_default_rules()
            print("rules", len(load_rules()), check_events([{"command": "bash -i"}])["match_count"])
            from modules.device_radar import check as radar
            print("radar", radar()["scanned"], "new", radar()["new_count"])
            from modules.ransomware_tripwire import deploy, check as tw
            print("tripwire deploy", deploy()["files"])
            print("tripwire check", tw()["count"])
            from modules.external_posture import check as ext
            print("external", ext()["ok"])
            from modules.fleet_console import collect_local
            print("fleet clients", len(collect_local()["clients"]))
            print("=== BONUS SELF-TEST OK ===")
        except Exception as e:
            print("[!] bonus-test:", e)

    
    elif command in ("dashboard", "dash", "ui"):
        try:
            from modules.dashboard import start_dashboard
            start_dashboard()
        except Exception as e:
            print("[!] dashboard:", e)
    elif command in ("dashboard-url", "dash-url"):
        try:
            from modules.dashboard import ensure_token
            tok, port, dash = ensure_token()
            print("http://127.0.0.1:%d/?token=%s" % (port, tok))
            print("control:", dash.get("allow_control", True))
        except Exception as e:
            print("[!] dashboard-url:", e)

    elif command == "uninstall":
        uninstall_sentinel(logger)
    else:
        logger.error(f"{C.RED}✗ Unknown command: {command}{C.RESET}")
        logger.info(f"Run {C.BOLD}sentinel{C.RESET} without arguments for help")
        sys.exit(1)


if __name__ == "__main__":
    main()
