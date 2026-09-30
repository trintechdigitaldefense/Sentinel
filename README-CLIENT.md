# 🛡️ Sentinel — Client-Ready Line of Defense

**TrinTech Digital Defense** · Trinidad & Tobago  
Continuous network monitoring, active deception, and early intrusion detection for businesses that need real visibility without a full SOC.

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Authorized%20Use%20Only-gray?style=for-the-badge)](#license)

---

## What Clients Get

| Capability | Description |
|------------|-------------|
| **Device Discovery** | Finds and fingerprints every device on agreed network segments |
| **Intrusion Detection** | Reverse shells, suspicious processes, new devices, auth failures |
| **Canary Traps** | Realistic decoy credentials & configs that alert when touched |
| **SSH Protection** | Automatic blocking of brute-force sources |
| **Integrity Monitoring** | Critical file and persistence location checks |
| **Clear Reports** | Professional PDF reports suitable for management |
| **Multi-host Agents** | Lightweight agents report into a central Sentinel (token-protected) |

**Designed for:** Small and medium businesses in the Caribbean that need continuous visibility and early warning, delivered as a supervised TrinTech service or carefully scoped self-hosted deployment.

---

## Quick Install (Client Environment)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
sudo bash install-sentinel.sh                  # central node
# OR
sudo bash install-sentinel.sh --agent http://CENTRAL_IP:8743
```

Then:

```bash
# On central
sudo systemctl enable --now sentinel-central
sentinel deception
sentinel integrity
sentinel pdf

# On agents (same shared_token required in config)
sudo systemctl enable --now sentinel-agent
```

Full hardening and deployment rules: see **[CLIENT_READY.md](CLIENT_READY.md)**.

---

## Core Commands

| Command | Purpose |
|---------|---------|
| `sentinel start` | Full scan + deception + hunt cycle |
| `sentinel deception` | Deploy realistic canaries/decoys |
| `sentinel canary` | Real-time canary watcher |
| `sentinel hunt` | Continuous monitoring loop |
| `sentinel processes` | Reverse-shell / suspicious process scan |
| `sentinel pdf` | Generate client PDF report |
| `sentinel central` | Start multi-host listener (token auth) |
| `sentinel agent <url>` | Run as reporting agent |
| `sentinel integrity` | Build/check FIM baseline |
| `sentinel uninstall` | Clean removal of data & services |

---

## Security Model (Client Deployments)

- Agent → Central communication requires a shared secret token
- Data directory permissions locked to owner (700/600)
- systemd services with restart + filesystem protection
- Self-integrity checks on startup
- Log rotation enabled
- Clean uninstall path provided

**Important limitations** are listed in `CLIENT_READY.md`. Do not deploy to a client network without completing the pre-deployment checklist.

---

## Managed Service Path

TrinTech offers Sentinel as part of a **Complete Protection Package**:

1. **Sentinel** — continuous monitoring & detection  
2. **Mirage** — active deception layer  
3. **Full Network Audit & Mapping**  
4. **Bi-weekly security reports**  
5. **Weekly free technical maintenance**

Contact: [trintechdigitaldefense@gmail.com](mailto:trintechdigitaldefense@gmail.com) · WhatsApp +1 (868) 362-0679

---

## License & Authorized Use

For **authorized defensive and security testing use only**.  
Unauthorized access to computer systems is illegal under the Trinidad & Tobago Cybercrimes Act and applicable international law.

---

**TrinTech Digital Defense** 🇹🇹  
*DEFEND. DETECT. DOMINATE.*
