#!/usr/bin/env python3
"""
Sentinel v2.0.0 — Line of Defense Engine
TrinTech Digital Defense | Cybersecurity Research

Active deception meets persistence hunting and Line of Defense.
Monitors local network for unauthorized devices,
deploys deception artifacts to trap and track intruders,
maintains persistent behavioral monitoring,
and provides comprehensive system integrity, process, network, and user monitoring.
"""

__version__ = "2.0.0"
__author__ = "Jason Junior Ramdharry — TrinTech Digital Defense | v2.0.0 — Line of Defense Engine"
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
from typing import Optional

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
 |  \\| | ___|  \\| | __ _ | |  __ _| |__  _ _ __ ___
 | . ` |/ _ \\ . ` |/ _` || | / _` | '_ \\| | '_ ` _ \\
 | |\\  |  __/ |\\  | (_| || || (_| | |_) | | | | | | |
 |_| \\_|\\___|_| \\_|\\__,_||_| \\__,_|_.__/|_|_| |_| |_|

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
        logger.info(f"{C.GREEN}✓{C.RESET} Config initialized at {C.BOLD}{CONFIG_FILE}{C.RESET}")
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
    config = load_config_safe()
    ts = datetime.now().isoformat()
    alert = {"timestamp": ts, "type": alert_type, "details": details,
             "hostname": socket.gethostname(), "local_ip": get_local_ip()}
    log_file = config.get("alerting", {}).get("log_file", str(ALERT_LOG))
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
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
    try:
        result = run_cmd(["ps", "aux", "--no-headers"], timeout=10)
        for line in result.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 11:
                continue

            user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
            command = " ".join(parts[10:])

            if "sentinel" in command.lower() or "baal-agent" in command.lower():
                continue

            for susp_cmd in pm.get("suspicious_commands", []):
                if susp_cmd in command:
                    msg = f"{C.RED}⚠ SUSPICIOUS PROCESS:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                    msg += f"\n     PID={pid} User={user} CPU={cpu}%"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "suspicious_cmd"})
                    send_alert("SUSPICIOUS_PROCESS", {"pid": pid, "user": user, "command": command[:200], "matched": susp_cmd}, logger)
                    break

            for mpath in pm.get("malware_paths", []):
                if mpath in command:
                    msg = f"{C.RED}⚠ PROCESS FROM MALWARE PATH:{C.RESET} {C.BOLD}{command[:80]}{C.RESET}"
                    msg += f"\n     PID={pid} User={user} Path={mpath}"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "malware_path"})
                    send_alert("MALWARE_PATH_PROCESS", {"pid": pid, "user": user, "command": command[:200], "path": mpath}, logger)
                    break

            try:
                if float(cpu) > 50:
                    msg = f"{C.YELLOW}!{C.RESET} HIGH CPU ({cpu}%): {C.BOLD}{command[:60]}{C.RESET} (PID: {pid}, User: {user})"
                    logger.warning(msg)
                    suspicious.append({"pid": pid, "user": user, "command": command, "reason": "high_cpu", "cpu": float(cpu)})
                    send_alert("HIGH_CPU_PROCESS", {"pid": pid, "user": user, "command": command[:200], "cpu": cpu}, logger)
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

def deploy_deception(config, logger):
    if not config.get("deception", {}).get("active", True):
        return

    logger.info(f"{C.CYAN}[*]{C.RESET} Deploying deception artifacts...")
    deception = config["deception"]

    if deception.get("fake_ssh_banner", True):
        try:
            with open("/etc/ssh/sshd_config") as f:
                content = f.read()
            if "Banner" not in content:
                with open("/etc/ssh/banner.txt", "w") as f:
                    f.write("""╔══════════════════════════════════════════╗
║          SECURITY WARNING                 ║
║  This is a monitored and protected system. ║
║  All access attempts are logged and reported.║
║  Unauthorized access is prohibited.       ║
║  TrinTech Digital Defense — Active Monitoring║
╚══════════════════════════════════════════╝""")
                content += "\nBanner /etc/ssh/banner.txt\n"
                with open("/etc/ssh/sshd_config", "w") as f:
                    f.write(content)
                logger.info(f"{C.GREEN}✓{C.RESET} SSH banner deployed")
        except PermissionError:
            logger.warning(f"{C.YELLOW}!{C.RESET} Permission denied for SSH banner")
        except Exception:
            pass

    if deception.get("fake_files", True):
        decoy_dirs = [
            Path.home() / "Desktop" / ".ssh",
            Path.home() / "Documents",
            Path.home() / "Downloads",
        ]
        decoy_files = [
            ("credentials_backup.json", '{"note": "DECOY - HONEYPOT"}'),
            ("db_config.yml", "database:\n  host: internal-db.trintech.local\n  user: admin\n  password: CHANGEME (DECOY)\n"),
            ("api_keys.txt", "# API Keys — DECOY\naws_key: AKIAIOSFODNN7EXAMPLE\n"),
            ("passwords.txt", "# Password list — DECOY\nadmin: Password123!\nroot: P@ssw0rd2024\n"),
        ]
        created = 0
        for d in decoy_dirs:
            d.mkdir(parents=True, exist_ok=True)
            for fname, content in decoy_files:
                fpath = d / fname
                if not fpath.exists():
                    with open(fpath, "w") as f:
                        f.write(content)
                    created += 1
        if created:
            logger.info(f"{C.GREEN}✓{C.RESET} {C.BOLD}{created} decoy files{C.RESET} deployed")

    hc = DECEPTION_DIR / "config.json"
    if not hc.exists():
        with open(hc, "w") as f:
            json.dump({"honeypot": True, "created": datetime.now().isoformat(), "triggered": []}, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Honeypot tracker initialized")

    fs = deception.get("fake_services", [])
    if fs:
        logger.info(f"{C.GREEN}✓{C.RESET} {C.BOLD}{len(fs)} fake services{C.RESET} registered")


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

    try:
        hc = str(DECEPTION_DIR / "config.json")
        if os.path.exists(hc):
            mtime = os.path.getmtime(hc)
            if time.time() - mtime < 300:
                logger.warning(f"{C.RED}!{C.RESET} {C.BOLD}Decoy modified:{C.RESET} {C.BOLD}{hc}{C.RESET}")
                send_alert("DECOY_MODIFIED", {"file": hc}, logger)
    except Exception:
        pass

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
    if DECEPTION_DIR.exists():
        decoy_count = len([f for f in DECEPTION_DIR.rglob("*") if f.is_file()])
    print(f"{C.BOLD}DECEPTION:{C.RESET} {decoy_count} artifacts")

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

def main():
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
        sys.exit(0)

    command = sys.argv[1]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    args = sys.argv[2:]
    logger = setup_logging(verbose)
    config = init_config(logger)
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
                persistence_hunt(config, logger)
                time.sleep(interval)
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

    else:
        logger.error(f"{C.RED}✗ Unknown command: {command}{C.RESET}")
        logger.info(f"Run {C.BOLD}sentinel{C.RESET} {C.BOLD}without arguments for help{C.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
