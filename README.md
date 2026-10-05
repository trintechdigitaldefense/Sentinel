# SENTINEL v2.5 — TrinTech Digital Defense

Continuous monitoring, active deception (canaries), reverse-shell detection, and early warning for **local SMB networks** — without a full SOC.

**Trinidad & Tobago · Caribbean-focused**

---

## Install (any device)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
```

That is the full setup: engine + Phase 4 + numbered menu + clean banner.

**Requirements:** Python 3.10+ (3.12 fine). Linux or Termux/Ubuntu. Root helps for some network checks but is not required for core features.

---

## How to use

```bash
cd Sentinel
python3 sentinel.py
```

**MAIN MENU**

| # | Action |
|---|--------|
| **1** | **Continuous protection** — scan + canaries once, then stay hunting |
| 2 | Quick network scan (one-shot) |
| 3 | Hunt only (continuous) |
| 4 | Deploy deception / canaries |
| 5 | Integrity baseline (FIM) — run once on new hosts |
| 6 | Process / reverse-shell scan |
| 7 | Report |
| 8 | Phase 4 (baseline, Caribbean pack, playbooks, evidence) |
| 9–12 | Info, alerts, hardening, status |
| 0 | Exit |

Or without the menu:

```bash
python3 sentinel.py start     # one-shot
python3 sentinel.py hunt      # continuous
python3 sentinel.py integrity
python3 sentinel.py baseline
python3 sentinel.py caribbean
python3 sentinel.py evidence --hours 24
python3 sentinel.py pdf       # if reportlab installed
```

### First hour on a client network

1. `python3 setup.py`
2. Edit scan range if needed: `~/.sentinel/config.json` → `network.scan_subnets` (e.g. `["192.168.1.0/24"]`)
3. Menu **5** — build FIM baseline
4. Menu **1** — leave continuous protection running
5. Later: menu **7** / `pdf` for client-facing report

---

## Where to deploy (local SMBs)

| Placement | Why |
|-----------|-----|
| **Office server / always-on PC** | Best: continuous hunt + canaries 24/7 |
| **Owner’s workstation** | Good visibility of that host + LAN scan |
| **Raspberry Pi / mini PC on LAN** | Low cost dedicated sensor |
| **Laptop only** | Works while online; not full-time coverage |

**Best practice for SMBs:** one always-on host on the main office LAN running menu **1** (or `hunt` under systemd).

Typical clients: small offices, retail, clinics, professional services, NGOs — anywhere with Windows/Linux devices, shared Wi‑Fi, and no SOC.

---

## What makes it client-ready

| Capability | Benefit for SMB |
|------------|-----------------|
| **Continuous hunt** | Ongoing process, cron, SSH, FIM checks |
| **Canary decoys** | Fake AWS keys, `.env`, passwords — alert if touched |
| **Reverse-shell patterns** | Detects common attacker shells |
| **FIM baseline** | Notices critical file changes |
| **Numbered menu** | Staff can operate without CLI memorization |
| **PDF / evidence pack** | Something you can hand the client |
| **Phase 4 playbooks** | Clear response steps (e.g. REVERSE_SHELL) |
| **Caribbean pack** | Regional-oriented checks |
| **Hardening + permissions** | Config/data locked down (600/700) |
| **Multi-host agents** | Optional: agents report to a central node |
| **One-command setup** | `python3 setup.py` after clone |

### Honest limits (set expectations)

- Not a replacement for EDR/firewall/patch management
- Network discovery depends on LAN visibility and permissions
- Outbound/`/proc` features may be limited on Termux/containers
- Authorization required — only networks you own or are contracted to defend

---

## Managed package (TrinTech)

1. **Sentinel** — continuous monitoring & detection
2. **Mirage** — deception layer
3. **Network audit & mapping** (periodic)
4. **Reports** (e.g. bi-weekly)
5. **Technical maintenance** (e.g. weekly)

**Contact:** trintechdigitaldefense@gmail.com · WhatsApp **+1 (868) 362-0679**

---

## Files you care about

| Path | Role |
|------|------|
| `setup.py` | **Only install step you need** |
| `sentinel.py` | Main tool (built by setup) |
| `modules/phase4.py` | Baseline, Caribbean, playbooks, evidence |
| `~/.sentinel/config.json` | Config (subnets, agents, alerts) |
| `~/.sentinel/data/` | Logs, baselines, canary tracker |

Do **not** run `restore_phase2/3/4.py` (legacy broken packs).

---

## License

Authorized defensive and security testing only.
Unauthorized access is illegal under applicable law (including Trinidad & Tobago Cybercrimes Act).

---

**TrinTech Digital Defense**
*Defend. Detect. Dominate.*
