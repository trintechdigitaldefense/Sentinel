# 🛡️ Sentinel v2.1 — Client-Ready Line of Defense

**TrinTech Digital Defense** · Trinidad & Tobago

Continuous network monitoring, active deception, reverse-shell detection, and early intrusion warning for businesses that need real visibility without a full SOC.

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.1.0%20Client--Ready-blue?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-Authorized%20Use%20Only-gray?style=for-the-badge)](#license)

---

## What is new in v2.1

- **Realistic canary decoys** (AWS keys, .env, SSH keys, DB configs) with unique IDs
- **Real-time canary watcher** (`sentinel canary`)
- **Enhanced reverse-shell detection** (bash -i, /dev/tcp, nc -e, python/perl/php shells, etc.)
- **Professional PDF reports** (`sentinel pdf`)
- **Multi-host agents** with shared-token authentication
- **Permission lockdown**, self-integrity checks, log rotation
- **systemd-ready** installer + clean uninstall
- Client deployment guide: [CLIENT_READY.md](CLIENT_READY.md)

---

## Quick start

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
sudo bash install-sentinel.sh                  # central
# or
sudo bash install-sentinel.sh --agent http://CENTRAL_IP:8743
```

```bash
sentinel deception    # plant canaries
sentinel integrity    # FIM baseline
sentinel hunt         # continuous monitoring
sentinel pdf          # client report
sentinel canary       # watch decoys live
```

---

## Core commands

| Command | Purpose |
|---------|---------|
| `start` | Full scan + deception + hunt |
| `deception` | Deploy realistic canaries |
| `canary` | Real-time canary watcher |
| `hunt` | Continuous monitoring |
| `processes` | Reverse-shell / process scan |
| `pdf` | Generate PDF report |
| `central` | Multi-host listener (token auth) |
| `agent <url>` | Report to central node |
| `integrity` | Build/check FIM baseline |
| `uninstall` | Clean removal |

Full hardening rules and client limitations: **[CLIENT_READY.md](CLIENT_READY.md)**  
Client-oriented overview: **[README-CLIENT.md](README-CLIENT.md)**

---

## Managed package (recommended for clients)

1. **Sentinel** — continuous monitoring & detection  
2. **Mirage** — active deception layer  
3. **Full Network Audit & Mapping**  
4. **Bi-weekly security reports**  
5. **Weekly technical maintenance**

Contact: trintechdigitaldefense@gmail.com · WhatsApp +1 (868) 362-0679

---

## License

For **authorized defensive and security testing use only**.  
Unauthorized access is illegal under the Trinidad & Tobago Cybercrimes Act and applicable international law.

---

**TrinTech Digital Defense** 🇹🇹  
*DEFEND. DETECT. DOMINATE.*
