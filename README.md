# 🛡️ Sentinel

> **TrinTech Digital Defense** — Advanced Device Activity Tracker  
> *Active Deception meets Persistence Hunting*

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Cybersecurity-Active%20Deception-red?style=for-the-badge)](https://www.metasploit.com)
[![License](https://img.shields.io/badge/License-Authorized%20Only-gray?style=for-the-badge)](#license)

---

## What is Sentinel?

**Sentinel** is an advanced device activity tracker and deception engine for penetration testers and security researchers. It combines passive network monitoring with active deception artifacts to detect, track, and engage unauthorized devices on your network.

Where traditional monitoring tools simply detect and alert, Sentinel goes further — it **deploys decoy artifacts** to trap intruders, **tracks behavioral patterns** over time, and maintains **persistent monitoring** that adapts to evolving threat patterns.

## Key Features

### 📡 Network Discovery & Monitoring
- Multi-subnet scanning with nmap (`-sn` host discovery + port enumeration)
- Automatic device fingerprinting (OS, vendor, MAC, hostname)
- Port service identification (`-sV` version detection)
- Persistent device database with first/last seen tracking
- New device detection with instant alerting

### 🪤 Active Deception Engine
- **Decoy files** planted in strategic directories (Desktop, Documents, Downloads)
  - Fake credentials, API keys, database configs, password lists
  - Honeypot tracker logs any modification or movement
- **Fake SSH banner** displays security warnings to intruders
- **Deceptive service registries** for common target ports (8080, 3306, 8443)
- File integrity monitoring on all deception artifacts

### 🐕 Persistence Hunting
- Continuous behavioral pattern monitoring
- Authentication failure tracking (journalctl SSH logs)
- Decoy file access monitoring with mtime tracking
- Alert on new devices, new ports, and auth failures
- Configurable monitoring intervals

### 🚨 Alert System
- Structured JSON alert logging (`~/.sentinel/data/alerts.log`)
- Email alerts via Gmail SMTP (configurable)
- Real-time console alerts with severity colors
- `sentinel alerts` command for quick review
- `tail -f` compatible log format for monitoring

### 📊 Reporting
- Comprehensive device report with port details
- Deception deployment status
- Recent alerts with severity classification
- System info with OS details and network configuration

## Installation

### Prerequisites
```bash
apt-get install -y nmap python3
```

### Quick Start
```bash
# Clone and make executable
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel

# Initialize config and run first scan
python3 sentinel.py start -v
```

### Setup as a System Command
```bash
sudo cp sentinel.py /usr/local/bin/sentinel
sudo chmod +x /usr/local/bin/sentinel

# Verify
sentinel --help
```

## Usage

### Core Commands

| Command | Description |
|---------|-------------|
| `sentinel start` | Full scan + deception deploy + persistence hunt |
| `sentinel scan` | Quick network scan with report |
| `sentinel report` | Show full device report |
| `sentinel status` | Show current Sentinel status |
| `sentinel deception` | Deploy deception artifacts |
| `sentinel hunt` | Start continuous persistence hunting |
| `sentinel config -v` | View current configuration |
| `sentinel alerts` | Show recent alerts |
| `sentinel info` | System information |
| `sentinel clean` | Reset all tracking data |

### Example Workflow

```bash
# 1. Deploy deception artifacts on a target machine
sentinel deception -v

# 2. Run initial network scan
sentinel scan

# 3. Check report for discovered devices
sentinel report

# 4. Start continuous monitoring (Ctrl+C to stop)
sentinel hunt

# 5. Check for any alerts
sentinel alerts
```

### Persistence Hunting Mode

The `hunt` command enters continuous monitoring mode:
```bash
sentinel hunt          # Default 60s interval
# Monitor SSH auth failures, decoy file access, new devices
# Press Ctrl+C to stop
```

### Email Alerts Setup

Edit `~/.sentinel/config.json`:
```json
{
  "alerting": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "from_email": "you@gmail.com",
      "app_password": "your-gmail-app-password",
      "to_email": "alerts@example.com"
    }
  }
}
```

## Architecture

```
sentinel/
├── sentinel.py          # Main engine (CLI, scan, deception, persistence)
├── data/                # Persistent state
│   ├── config.json      # Configuration
│   ├── devices.json     # Device database
│   ├── alerts.log       # Alert log
│   └── deception_artifacts/
│       └── config.json  # Honeypot tracker
└── decoy/               # Decoy files (planted by deception engine)
    ├── Desktop/.ssh/
    ├── Documents/
    └── Downloads/
```

## Configuration

All configuration is stored in `~/.sentinel/config.json`:

```json
{
  "network": {
    "scan_interval": 30,
    "scan_ports": "22,80,443,8080,3306,5432,27017,6379,8443,9200",
    "scan_subnets": ["192.168.1.0/24", "10.0.0.0/8"]
  },
  "deception": {
    "active": true,
    "fake_services": [
      {"port": 8080, "service": "admin-panel", "banner": "TrinTech Admin"},
      {"port": 3306, "service": "mysql-decoy", "banner": "MySQL 5.7 (DECOY)"}
    ],
    "fake_files": true,
    "fake_ssh_banner": true
  },
  "alerting": {
    "email": { "enabled": false, ... },
    "log_file": "~/.sentinel/data/alerts.log"
  },
  "persistence": {
    "monitor_interval": 60,
    "alert_on_new_device": true,
    "alert_on_auth_failure": true
  }
}
```

## Sample Output

```
$ sentinel scan

  _   _      _   _        _     _______ _
 | \ | |    | \ | |      | |   |__   __(_)
 |  \| | ___|  \| | __ _ | |  __ _| |__  _ _ __ ___
 | . ` |/ _ \ . ` |/ _` || | / _` | '_ \| | '_ ` _ \
 | |\  |  __/ |\  | (_| || || (_| | |_) | | | | | | |
 |_| \_|\___|_| \_|\__,_||_| \__,_|_.__/|_|_| |_| |_|

 SENTINEL v1.0.0
 TrinTech Digital Defense — Cybersecurity Research & Tool Repository
 Active Deception meets Persistence Hunting

[*] Scanning 1 subnets: 192.168.1.0/24
[*] Ports: 22,80,443,8080,3306
[!] NEW DEVICE DETECTED — guest-phone (192.168.1.142)
✓ Scanned 1 subnets — 5 devices discovered

  === SENTINEL REPORT ===
  Generated: 2026-07-27 10:30:00
  Host:      workstation
  IP:        192.168.1.10
  Scans:     1
  Devices:   5

  ● workstation (192.168.1.10)
    IP:   192.168.1.10
    MAC:  52:54:00:12:34:56
    Ports: 22/ssh, 80/http
    Last seen: today

  ● guest-phone (192.168.1.142)  ← NEW
    IP:   192.168.1.142
    MAC:  aa:bb:cc:dd:ee:ff
    Ports: none
    Last seen: today
```

## License

All tools and frameworks in Sentinel are designed for **authorized security testing only**. Unauthorized access to computer systems is illegal under Trinidad & Tobago's Cybercrimes Act and international law.

---

**TrinTech Digital Defense** 🇹🇹  
*Professional cybersecurity consulting · Trinidad & Tobago*

[🌐 Website](https://trintechdigitaldefense.github.io) ·
[📧 Contact](mailto:trintechdigitaldefense@gmail.com) ·
[💼 LinkedIn](https://www.linkedin.com/in/trintech-digital-defense-a68614407)

---

*DEFEND. DETECT. DOMINATE.* 🛡️
