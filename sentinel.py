#!/usr/bin/env python3
"""
Sentinel — Advanced Device Activity Tracker
TrinTech Digital Defense | Cybersecurity Research

Active deception meets persistence hunting.
Monitors local network for unauthorized devices,
deploys deception artifacts to trap and track intruders,
and maintains persistent behavioral monitoring.
"""

__version__ = "1.0.0"
__author__ = "Jason Junior Ramdharry — TrinTech Digital Defense"
__license__ = "For authorized security testing only"

import sys
import os
import json
import subprocess
import socket
import time
import signal
import argparse
import logging
import hashlib
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
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
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
{C.GRAY}Active Deception meets Persistence Hunting{C.RESET}
{C.GRAY}{'_' * 50}{C.RESET}
""")


# ── Configuration ──
def init_config(logger):
    SENTINEL_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DECEPTION_DIR.mkdir(parents=True, exist_ok=True)

    default_config = {
        "version": __version__,
        "created": datetime.now().isoformat(),
        "network": {
            "scan_interval": 30,          # seconds between scans
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
            "fake_files": True,          # create decoy files on filesystem
            "fake_ssh_banner": True,     # misleading SSH banner
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
            "monitor_interval": 60,       # seconds between behavioral checks
            "alert_on_new_device": True,
            "alert_on_new_port": True,
            "alert_on_auth_failure": True,
        },
    }

    config = default_config  # default in both cases
    if CONFIG_FILE.exists():
        # Load and upgrade if needed
        with open(CONFIG_FILE) as f:
            config = json.load(f)
        # Merge defaults
        for key in default_config:
            if key not in config:
                config[key] = default_config[key]
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Config loaded from {C.BOLD}{CONFIG_FILE}{C.RESET}")
    else:
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Config initialized at {C.BOLD}{CONFIG_FILE}{C.RESET}")

    return config


# ── Device Database ──
def load_devices():
    if DEVICE_DB.exists():
        with open(DEVICE_DB) as f:
            return json.load(f)
    return {"devices": {}, "first_seen": {}, "last_seen": {}, "total_scans": 0}


def save_devices(data):
    with open(DEVICE_DB, "w") as f:
        json.dump(data, f, indent=2, default=str)


# ── Network Scanner ──
def get_local_ip():
    """Get the primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_my_mac():
    """Get local MAC address."""
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "link/ether" in line:
                return line.split("link/ether ")[1].split()[0]
    except Exception:
        pass
    return "00:00:00:00:00:00"


def scan_network(config, logger, data=None):
    """Scan all configured subnets using nmap. Returns list of discovered hosts."""
    subnets = config.get("network", {}).get("scan_subnets", ["192.168.1.0/24"])
    # Filter out huge subnets (/12 and larger) to avoid long scans in VM/container environments
    effective_subnets = [s for s in subnets if int(s.split("/")[1]) not in (12, 11, 10)]
    if not effective_subnets:
        effective_subnets = ["192.168.1.0/24"]
    subnets = effective_subnets
    ports = config.get("network", {}).get("scan_ports", "22,80,443,8080")
    local_ip = get_local_ip()
    my_mac = get_my_mac()
    discovered = []
    first_seen = (data or {}).get("first_seen", {})
    last_seen = (data or {}).get("last_seen", {})
    data = data or {"devices": {}, "first_seen": {}, "last_seen": {}, "total_scans": 0}

    logger.info(f"{C.CYAN}[*]{C.RESET} Scanning {len(subnets)} subnets: {', '.join(subnets)}")
    logger.info(f"{C.CYAN}[*]{C.RESET} Ports: {ports}")

    # Use nmap for scanning
    try:
        for subnet in subnets:
            cmd = [
                "nmap", "-sn", "-oJ", "/tmp/sentinel_scan.json",
                "--host-timeout", "2s",
                "--min-rate", "1000",
                "-T4",
                "--send-ip",
                subnet,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                if "timeout" in result.stderr.lower() or "timed out" in result.stderr.lower():
                    logger.warning(f"{C.YELLOW}!{C.RESET} Scan of {C.BOLD}{subnet}{C.RESET} timed out (no response — may be isolated container)")
                else:
                    logger.warning(f"{C.YELLOW}!{C.RESET} Scan of {C.BOLD}{subnet}{C.RESET} failed: {result.stderr[:100]}")
                os.remove("/tmp/sentinel_scan.json") if os.path.exists("/tmp/sentinel_scan.json") else None
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
                            "ip": ipv4,
                            "mac": mac,
                            "hostname": hostname or ipv4,
                            "vendor": vendor if vendor != "Unknown" else "Unknown",
                            "ports": [],
                            "first_seen": first_seen.get(ipv4, datetime.now().isoformat()),
                            "last_seen": datetime.now().isoformat(),
                        }

                        # Scan open ports
                        port_cmd = [
                            "nmap", "-sV", "-p", ports, "-oJ", "/tmp/sentinel_ports.json",
                            "--host-timeout", "2s", "--min-rate", "500", "-T4",
                            ipv4
                        ]
                        port_result = subprocess.run(port_cmd, capture_output=True, text=True, timeout=30)
                        if port_result.returncode == 0 and os.path.exists("/tmp/sentinel_ports.json"):
                            with open("/tmp/sentinel_ports.json") as f:
                                port_data = json.load(f)
                            for h in port_data.get("scanresults", {}).get("hosts", []):
                                for port in h.get("ports", {}).get("port", []):
                                    device["ports"].append({
                                        "port": port.get("portid", ""),
                                        "state": port.get("state", {}).get("state", "closed"),
                                        "service": port.get("service", {}).get("name", "unknown"),
                                        "version": port.get("service", {}).get("product", "")
                                    })

                        # Track alerts
                        if ipv4 != local_ip:
                            if ipv4 not in first_seen:
                                logger.warning(f"{C.RED}⚠ NEW DEVICE DETECTED{C.RESET} — {device['hostname']} ({ipv4})")
                                if config.get("persistence", {}).get("alert_on_new_device", True):
                                    send_alert("NEW_DEVICE", device)
                            first_seen[ipv4] = datetime.now().isoformat()

                        if ipv4 not in (mac):
                            last_seen[ipv4] = datetime.now().isoformat()

                        discovered.append(device)

                os.remove("/tmp/sentinel_scan.json")

        # Save to device database
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


# ── Active Deception Engine ──
def deploy_deception(config, logger):
    """Deploy deception artifacts to trap and track intruders."""
    if not config.get("deception", {}).get("active", True):
        logger.info(f"{C.GRAY}[*]{C.RESET} Deception is disabled in config")
        return

    logger.info(f"{C.CYAN}[*]{C.RESET} Deploying deception artifacts...")
    deception = config["deception"]

    # 1. Fake SSH banner
    if deception.get("fake_ssh_banner", True):
        banner_file = "/etc/ssh/sshd_config"
        try:
            with open(banner_file) as f:
                content = f.read()
            if "Banner" not in content:
                banner_text_file = "/etc/ssh/banner.txt"
                with open(banner_text_file, "w") as f:
                    f.write("""╔══════════════════════════════════════════╗
║          SECURITY WARNING                 ║
║  This is a monitored and protected system. ║
║  All access attempts are logged and reported.║
║  Unauthorized access is prohibited.       ║
║  TrinTech Digital Defense — Active Monitoring║
╚══════════════════════════════════════════╝""")
                content += "\nBanner /etc/ssh/banner.txt\n"
                with open(banner_file, "w") as f:
                    f.write(content)
                logger.info(f"{C.GREEN}✓{C.RESET} SSH banner deployed to {C.BOLD}{banner_text_file}{C.RESET}")
        except PermissionError:
            logger.warning(f"{C.YELLOW}!{C.RESET} Permission denied deploying SSH banner (run as root)")
        except Exception as e:
            logger.warning(f"{C.YELLOW}!{C.RESET} SSH banner deploy failed: {e}")

    # 2. Decoy files on filesystem
    if deception.get("fake_files", True):
        decoy_dirs = [
            Path.home() / "Desktop" / ".ssh",
            Path.home() / "Documents",
            Path.home() / "Downloads",
        ]
        decoy_files = [
            ("credentials_backup.json", '{"note": "DECOY - DO NOT USE - This is a honeypot file"}'),
            ("db_config.yml", "database:\n  host: internal-db.trintech.local\n  user: admin\n  password: CHANGEME (DECOY)\n"),
            ("api_keys.txt", "# API Keys for Internal Services\n# WARNING: These are decoy credentials\naws_key: AKIAIOSFODNN7EXAMPLE\n"),
            ("passwords.txt", "# Password list - DECOY ONLY\nadmin: Password123!\nroot: P@ssw0rd2024\n"),
        ]
        created = 0
        for decoy_dir in decoy_dirs:
            decoy_dir.mkdir(parents=True, exist_ok=True)
            for filename, content in decoy_files:
                fpath = decoy_dir / filename
                if not fpath.exists():
                    with open(fpath, "w") as f:
                        f.write(content)
                    created += 1
                    logger.info(f"{C.GREEN}✓{C.RESET} Decoy file created: {C.BOLD}{fpath}{C.RESET}")
                else:
                    logger.info(f"{C.GRAY}·{C.RESET} Decoy file exists: {C.BOLD}{fpath}{C.RESET}")

        if created > 0:
            logger.info(f"{C.GREEN}✓{C.RESET} {C.BOLD}{created} decoy files{C.RESET} deployed across {len(decoy_dirs)} directories")

    # 3. Decoy honeypot files in deception dir
    decoy_config = DECEPTION_DIR / "config.json"
    if not decoy_config.exists():
        with open(decoy_config, "w") as f:
            json.dump({
                "honeypot": True,
                "created": datetime.now().isoformat(),
                "triggered": [],
                "description": "If this file is modified or moved, an alert will be generated.",
            }, f, indent=2)
        logger.info(f"{C.GREEN}✓{C.RESET} Honeypot tracker initialized: {C.BOLD}{decoy_config}{C.RESET}")

    # 4. Fake service descriptions (logged, not actually running)
    fake_services = deception.get("fake_services", [])
    if fake_services:
        logger.info(f"{C.GREEN}✓{C.RESET} {C.BOLD}{len(fake_services)} fake services{C.RESET} registered:")
        for svc in fake_services:
            logger.info(f"   {C.YELLOW}•{C.RESET} Port {C.BOLD}{svc['port']}{C.RESET} — {svc['service']} ({svc.get('banner', '')})")
        logger.info(f"{C.GRAY}   (Services are tracked but not actively exposed — log deception artifacts for later use){C.RESET}")


# ── Persistence Hunter ──
def persistence_hunt(config, logger):
    """
    Persistence hunting module.
    Continuously monitors for new activity patterns:
    - New devices connecting
    - New open ports on known devices
    - Authentication failures
    - Unauthorized file access (decoys)
    """
    if logger is None:
        logger = logging.getLogger("sentinel")
    logger.info(f"{C.CYAN}[*]{C.RESET} Persistence hunt mode active")
    logger.info(f"{C.CYAN}[*]{C.RESET} Monitoring behavioral patterns...")

    interval = config.get("persistence", {}).get("monitor_interval", 60)

    # Monitor auth failures
    try:
        import subprocess
        result = subprocess.run(["journalctl", "-u", "ssh", "--since", "1 hour ago", "-n", "100"],
                                capture_output=True, text=True, timeout=10)
        auth_failures = [line for line in result.stdout.split("\n") if "Failed password" in line]
        if auth_failures:
            logger.warning(f"{C.RED}!{C.RESET} {C.BOLD}{len(auth_failures)} SSH authentication failures{C.RESET} detected in last hour")
            if config.get("persistence", {}).get("alert_on_auth_failure", True):
                send_alert("AUTH_FAILURE", {"failures": len(auth_failures), "samples": auth_failures[:5]})
    except Exception:
        pass

    # Monitor decoy file access
    try:
        import os
        decoy_files_list = [
            str(DECEPTION_DIR / "config.json"),
        ]
        for fpath in decoy_files_list:
            try:
                mtime = os.path.getmtime(fpath)
                # If file was modified recently, alert
                if time.time() - mtime < 300:  # within 5 min
                    logger.warning(f"{C.RED}!{C.RESET} {C.BOLD}Decoy file modified{C.RESET}: {C.BOLD}{fpath}{C.RESET}")
                    send_alert("DECOY_MODIFIED", {"file": fpath, "mtime": datetime.fromtimestamp(mtime).isoformat()})
            except Exception:
                pass
    except Exception:
        pass

    return True


# ── Alert System ──
def send_alert(alert_type, details, logger=None):
    """Send alert via configured channels."""
    config = load_config_safe()
    ts = datetime.now().isoformat()

    alert = {
        "timestamp": ts,
        "type": alert_type,
        "details": details,
        "hostname": socket.gethostname(),
        "local_ip": get_local_ip(),
    }

    # Log to file
    log_file = config.get("alerting", {}).get("log_file", str(ALERT_LOG))
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:
        pass

    # Email if configured
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

            body = f"""SENTINEL SECURITY ALERT
Type: {alert_type}
Time: {ts}
Host: {socket.gethostname()}
IP: {get_local_ip()}
Details: {json.dumps(details, indent=2)}
"""
            msg.attach(MIMEText(body, "plain"))

            smtp = smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"])
            smtp.starttls()
            smtp.login(email_cfg["from_email"], email_cfg.get("app_password", ""))
            smtp.sendmail(email_cfg["from_email"], email_cfg["to_email"], msg.as_string())
            smtp.quit()
            logger = logging.getLogger("sentinel")
            logger.info(f"{C.GREEN}✓{C.RESET} Alert sent via email: {C.BOLD}{alert_type}{C.RESET}")
        except Exception as e:
            logger = logging.getLogger("sentinel")
            logger.warning(f"{C.YELLOW}!{C.RESET} Email alert failed: {e}")


def load_config_safe():
    """Safely load config, return defaults if missing."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"alerting": {"email": {}}, "persistence": {}, "deception": {}}


# ── Reports ──
def generate_report(data, config, logger):
    """Generate a comprehensive report of all findings."""
    devices = data.get("devices", {})
    first_seen = data.get("first_seen", {})
    total_scans = data.get("total_scans", 0)

    print(f"""

{C.BOLD}{'=' * 60}
{C.BOLD}{C.CYAN}  SENTINEL REPORT{C.RESET}
{C.BOLD}{'=' * 60}
{C.BOLD}Generated:{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{C.BOLD}Host:{C.RESET}      {socket.gethostname()}
{C.BOLD}IP:{C.RESET}        {get_local_ip()}
{C.BOLD}MAC:{C.RESET}       {get_my_mac()}
{C.BOLD}Scans:{C.RESET}     {total_scans}
{C.BOLD}Devices:{C.RESET}   {C.BOLD}{len(devices)}{C.RESET}
{C.BOLD}{'=' * 60}{C.RESET}
""")

    if devices:
        print(f"{C.BOLD}{C.BLUE}DISCOVERED DEVICES{C.RESET}")
        print(f"{'-' * 60}")
        for ip, dev in sorted(devices.items()):
            seen_days = (datetime.now() - datetime.fromisoformat(dev["last_seen"])).days
            age = f"{seen_days}d" if seen_days > 0 else "today"
            ports_info = ", ".join(
                f"{p['port']}/{p['service']}" for p in dev.get("ports", []) if p.get("state") == "open"
            ) or "none"

            status_color = C.GREEN
            if "decoy" in dev.get("hostname", "").lower() or "honeypot" in dev.get("hostname", "").lower():
                status_color = C.YELLOW

            print(f"""
  {C.BOLD}{status_color}●{C.RESET} {C.BOLD}{dev['hostname'] or ip}{C.RESET}
    IP:   {ip}
    MAC:  {dev.get('mac', 'N/A')}
    Vendor: {dev.get('vendor', 'Unknown')}
    Ports: {ports_info}
    Last seen: {dev['last_seen']} ({age})
    First seen: {first_seen.get(ip, 'Unknown')}""")

        print(f"\n{C.BOLD}{'-' * 60}{C.RESET}")
    else:
        print(f"\n{C.BOLD}{C.YELLOW}No devices discovered yet. Run 'sentinel start' first.{C.RESET}\n")

    # Deception status
    decoy_count = 0
    if DECEPTION_DIR.exists():
        decoy_count = len([f for f in DECEPTION_DIR.rglob("*") if f.is_file()])
    print(f"{C.BOLD}DECEPTION STATUS:{C.RESET}")
    print(f"  Decoy artifacts: {C.BOLD}{decoy_count}{C.RESET} files")

    if os.path.exists("/etc/ssh/sshd_config") and "Banner" in open("/etc/ssh/sshd_config").read():
        print(f"  SSH banner:    {C.GREEN}✓ deployed{C.RESET}")
    else:
        print(f"  SSH banner:    {C.RED}✗ not deployed{C.RESET}")

    # Alerts log
    if os.path.exists(str(ALERT_LOG)):
        with open(ALERT_LOG) as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        if alerts:
            print(f"\n{C.BOLD}RECENT ALERTS ({len(alerts)}){C.RESET}")
            for alert in alerts[-10:]:
                severity = C.RED
                if alert.get("type") in ("NEW_DEVICE", "DECOY_MODIFIED"):
                    severity = C.RED
                elif alert.get("type") == "AUTH_FAILURE":
                    severity = C.YELLOW
                else:
                    severity = C.BLUE
                print(f"  {severity}●{C.RESET} [{alert['timestamp']}] {C.BOLD}{alert['type']}{C.RESET}")

    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")


# ── Status ──
def show_status(data, config, logger):
    """Show current Sentinel status."""
    devices = data.get("devices", {})
    total_scans = data.get("total_scans", 0)
    deception_active = config.get("deception", {}).get("active", True)

    print(f"""
{C.BOLD}{'=' * 50}
{C.BOLD}{C.CYAN}  SENTINEL STATUS{C.RESET}
{C.BOLD}{'=' * 60}
{C.BOLD}Version:{C.RESET}   {__version__}
{C.BOLD}Host:{C.RESET}      {socket.gethostname()}
{C.BOLD}Local IP:{C.RESET}  {get_local_ip()}
{C.BOLD}MAC:{C.RESET}       {get_my_mac()}
{C.BOLD}Total Scans:{C.RESET} {total_scans}
{C.BOLD}Devices:{C.RESET}    {C.BOLD}{len(devices)}{C.RESET}
{C.BOLD}Deception:{C.RESET} {C.GREEN}{'ACTIVE' if deception_active else 'OFF'}{C.RESET}
{C.BOLD}{'=' * 60}{C.RESET}
""")


# ── Main CLI ──
def main():
    if len(sys.argv) < 2:
        banner()
        print(f"{C.BOLD}{C.BLUE}USAGE:{C.RESET}")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}start[ -v]{C.RESET}          Run scan + deploy deception")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}scan[ -v]{C.RESET}               Quick network scan")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}report{C.RESET}               Show full report")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}status{C.RESET}               Show current status")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}config[ -v]{C.RESET}           Initialize/edit config")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}alerts{C.RESET}                Show recent alerts")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}deception{C.RESET}            Deploy deception artifacts")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}hunt[ -v]{C.RESET}                  Start persistence hunting mode")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}info{C.RESET}                    System info")
        print(f"  {C.BOLD}sentinel{C.RESET} {C.CYAN}clean{C.RESET}                   Reset all tracking data")
        print()
        sys.exit(0)

    command = sys.argv[1]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    logger = setup_logging(verbose)

    # Initialize config (needed for all commands)
    config = init_config(logger)

    banner()

    if command == "start":
        data = load_devices()
        scan_network(config, logger, data)
        deploy_deception(config, logger)
        persistence_hunt(config, logger)
        report = generate_report(data, config, logger)

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
        logger.info(f"{C.CYAN}[*]{C.RESET} Persistence hunting mode — press Ctrl+C to stop")
        interval = config.get("persistence", {}).get("monitor_interval", 60)
        try:
            while True:
                persistence_hunt(config, logger)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info(f"{C.GREEN}✓{C.RESET} Persistence hunting stopped")

    elif command == "config":
        if verbose:
            print(f"{C.BOLD}Configuration file:{C.RESET} {C.BOLD}{CONFIG_FILE}{C.RESET}")
            print(f"\n{C.BOLD}Contents:{C.RESET}")
            with open(CONFIG_FILE) as f:
                print(f.read())
            print(f"\nEdit with: nano {CONFIG_FILE}")
        else:
            logger.info(f"{C.BOLD}Config file:{C.RESET} {C.BOLD}{CONFIG_FILE}{C.RESET}")
            logger.info(f"{C.BOLD}Run{C.RESET} {C.BOLD}sentinel config -v{C.RESET} {C.BOLD}to view contents{C.RESET}")

    elif command == "alerts":
        """Show recent alerts from log."""
        if os.path.exists(str(ALERT_LOG)):
            with open(ALERT_LOG) as f:
                alerts = [json.loads(line) for line in f if line.strip()]
            if alerts:
                print(f"\n{C.BOLD}{C.RED}RECENT ALERTS ({len(alerts)}){C.RESET}")
                print(f"{'─' * 60}")
                for alert in alerts[-50:]:
                    severity = C.RED if alert.get("type") in ("NEW_DEVICE", "DECOY_MODIFIED") else C.YELLOW
                    if alert.get("type") == "AUTH_FAILURE":
                        severity = C.RED
                    print(f"  {severity}●{C.RESET} [{alert['timestamp']}] {C.BOLD}{alert['type']}{C.RESET} — {json.dumps(alert.get('details', {}))}")
                print(f"\n{C.BOLD}Log file:{C.RESET} {C.BOLD}{ALERT_LOG}{C.RESET}")
                print(f"{C.BOLD}Follow:{C.RESET}  {C.BOLD}tail -f {ALERT_LOG}{C.RESET}")
            else:
                print(f"\n{C.BOLD}{C.GREEN}No alerts recorded.{C.RESET}")
        else:
            print(f"\n{C.BOLD}{C.GREEN}No alerts recorded yet. Run 'sentinel start' first.{C.RESET}")

    elif command == "clean":
        """Reset device database and alerts."""
        if DEVICE_DB.exists():
            DEVICE_DB.unlink()
            logger.info(f"{C.GREEN}✓{C.RESET} Device database cleared")
        if ALERT_LOG.exists():
            ALERT_LOG.unlink()
            logger.info(f"{C.GREEN}✓{C.RESET} Alert log cleared")
        print(f"{C.GREEN}{C.BOLD}All tracking data reset.{C.RESET} Run 'sentinel start' to begin fresh.")

    elif command == "info":
        """Show Sentinel info and system details."""
        devices = load_devices()
        total_scans = devices.get("total_scans", 0)
        device_count = len(devices.get("devices", {}))

        print(f"\n{C.BOLD}{C.CYAN}SENTINEL SYSTEM INFO{C.RESET}")
        print(f"{'─' * 50}")
        print(f"  {C.BOLD}Version:{C.RESET}      {__version__}")
        print(f"  {C.BOLD}Author:{C.RESET}      {__author__}")
        print(f"  {C.BOLD}Host:{C.RESET}        {socket.gethostname()}")
        print(f"  {C.BOLD}Local IP:{C.RESET}    {get_local_ip()}")
        print(f"  {C.BOLD}MAC:{C.RESET}         {get_my_mac()}")
        print(f"  {C.BOLD}Data Dir:{C.RESET}    {DATA_DIR}")
        print(f"  {C.BOLD}Config:{C.RESET}      {CONFIG_FILE}")
        print(f"  {C.BOLD}Total Scans:{C.RESET} {total_scans}")
        print(f"  {C.BOLD}Tracked Devices:{C.RESET} {device_count}")
        print()

        # Show system info
        try:
            result = subprocess.run(["uname", "-a"], capture_output=True, text=True, timeout=5)
            print(f"  {C.BOLD}OS:{C.RESET}         {result.stdout.strip()}")
        except Exception:
            pass

        print(f"{'─' * 50}\n")

    else:
        logger.error(f"{C.RED}✗ Unknown command: {command}{C.RESET}")
        logger.info(f"{C.BOLD}Run{C.RESET} {C.BOLD}sentinel{C.RESET} {C.BOLD}without arguments for help{C.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
