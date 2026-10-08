# Sentinel — Continuous Line of Defense

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹

Always-on monitoring and early warning for local SMB networks that do not have a full SOC.

Sentinel detects reverse shells, watches critical files, deploys canary decoys, and provides clear alerts and reports. Pair it with **Mirage** for active deception and with **FortifyOne** for the initial professional network audit.

---

## Quick Start

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py
```

**Requirements:** Python 3.10+ · Linux or Termux/Ubuntu

---

## Main Menu

| # | Action |
|---|--------|
| **1** | **Continuous protection** — scan + canaries, then stay hunting |
| 2 | Quick network scan (one-shot) |
| 3 | Hunt only (continuous) |
| 4 | Deploy deception / canaries |
| 5 | Integrity baseline (FIM) |
| 6 | Process / reverse-shell scan |
| 7 | Report |
| 8 | Phase 4 (Caribbean pack, playbooks, evidence) |
| 0 | Exit |

CLI shortcuts:
```bash
python3 sentinel.py hunt
python3 sentinel.py integrity
python3 sentinel.py evidence --hours 24
python3 sentinel.py pdf
```

---

## Recommended Client Deployment

1. Run `python3 setup.py`
2. Set scan range in `~/.sentinel/config.json` → `network.scan_subnets`
3. Build FIM baseline (menu 5)
4. Start continuous protection (menu 1) or run under systemd
5. Deliver reports via menu 7 / PDF

**Best placement:** always-on office server, mini PC, or Raspberry Pi on the main LAN.

Typical clients: small offices, retail, clinics, professional services, NGOs.

---

## What Clients Actually Get

- Continuous process, SSH, and FIM monitoring
- Canary files (fake credentials, .env, keys) that alert on touch
- Reverse-shell pattern detection
- Clear PDF / evidence output
- Caribbean-oriented checks and response playbooks
- Simple numbered menu — no deep CLI knowledge required

**Honest limits**
- Not a full EDR or SIEM replacement
- Network visibility depends on placement and permissions
- Authorized use only

---

## Continuous Protection Package

| Component | Role |
|-----------|------|
| **FortifyOne** | Professional point-in-time network audit |
| **Sentinel** | Continuous monitoring & early warning |
| **Mirage** | Active deception layer (fake services + honey tokens) |

Together these form a practical offering for Trinidad & Tobago and Caribbean SMBs.

---

## Contact

**TrinTech Digital Defense**  
Email: trintechdigitaldefense@gmail.com  
WhatsApp: +1 (868) 362-0679  
Web: https://trintechdigitaldefense.github.io

---

Authorized defensive use only.  
Unauthorized access is illegal under the Trinidad & Tobago Cybercrime Act and applicable law.

*Defend. Detect. Dominate.*
