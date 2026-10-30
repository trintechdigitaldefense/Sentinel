# SENTINEL — Overview, How to Use & Cheatsheet

**Product:** Sentinel continuous monitoring & early warning  
**Vendor:** TrinTech Digital Defense (Trinidad & Tobago / Caribbean)  
**Version:** 3.16.21+ (hardening/production-readiness branch)  
**Use:** Authorized defensive use only

---

## 1. What Sentinel is

Sentinel is a host-focused **line of defense** for Caribbean SMBs:

| Capability | Plain language |
|------------|----------------|
| Persistence hunting | Watches cron, SSH, users, suspicious processes, reverse-shell style activity |
| Canary deception | Plants decoy files (credentials, keys, .env) that alert when touched |
| File integrity (FIM) | Baseline of important files; alerts on unexpected changes |
| SSH / brute-force assist | Detects repeated failures; blocking is **opt-in** (safe defaults) |
| Host firewall control plane | nft/iptables profiles with **dry-run default** — not a perimeter appliance |
| Alerts | Local log, optional WhatsApp / email / webhook / SIEM (e.g. Splunk HEC) |
| Dashboard | Local web UI: status, criticals, actions, one-click PDF reports |
| Evidence / PDF | Owner-friendly PDF with logo; technical exports for operators |
| Service mode | Always-on hunt via systemd or Termux-safe background |

**It is not:** a full SOC, a cloud EDR replacement, or a guarantee of “no compromise.”

---

## 2. Install (single path)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
# Prefer hardening branch until merged to main:
git fetch origin && git checkout hardening/production-readiness
python3 setup.py
python3 sentinel.py doctor
```

Config: `~/.sentinel/config.json` (mode `0600`)  
Data/logs: `~/.sentinel/data/`

---

## 3. Daily use

### Interactive menu
```bash
python3 sentinel.py
```

### Core commands
| Command | Purpose |
|---------|---------|
| `python3 sentinel.py start` | One scan + deception + line-of-defense checks |
| `python3 sentinel.py hunt` | Continuous persistence hunt (Ctrl+C stops) |
| `python3 sentinel.py deception` | Deploy / refresh canaries |
| `python3 sentinel.py integrity` | Build FIM baseline |
| `python3 sentinel.py integrity --check` | Check against baseline |
| `python3 sentinel.py go-live` | Guided readiness (canaries + baselines) |
| `python3 sentinel.py doctor` | Health / pilot health checklist |
| `python3 sentinel.py service-install` | Always-on service (systemd or bg hunt) |
| `python3 sentinel.py service-status` | Service state |
| `python3 sentinel.py dashboard` | Local UI (leave running) |
| `python3 sentinel.py dashboard-url` | Print URL + token |
| `python3 sentinel.py report` / PDF via dashboard | Client PDF |
| `python3 sentinel.py quiet on\|off` | Quiet hours |
| `python3 sentinel.py processes` | Suspicious process scan |
| `python3 sentinel.py hardening` | Hardening audit |
| `python3 sentinel.py evidence` | Evidence pack |

### Dashboard PDF (one click)
1. `python3 sentinel.py dashboard` — **leave running**
2. Open printed URL (`?token=...`)
3. Tap **Generate PDF report** / **Generate & view client PDF**
4. PDF opens with TrinTech logo, verdict, protection table, next steps

Direct: `http://127.0.0.1:8792/api/report/pdf?token=YOUR_TOKEN`

### Set client name on reports
```bash
python3 -c "
import json; from pathlib import Path
p=Path.home()/'.sentinel'/'config.json'
c=json.loads(p.read_text())
c.setdefault('dashboard',{})['client_name']='Your Client Ltd'
p.write_text(json.dumps(c,indent=2))
"
```

---

## 4. Pilot sequence (recommended)

1. `doctor` → fix FAILs  
2. `go-live` / `deception` + `integrity`  
3. `service-install` or overnight `hunt`  
4. Force a **canary touch** and confirm alert path  
5. Generate **client PDF** for the owner  
6. Optional: WhatsApp / Splunk channel when credentials exist  
7. Field-soak 1–2 weeks before calling it “steady”

---

## 5. Safety defaults (important)

- SSH **auto-block defaults off** (opt-in autonomy)  
- Firewall **dry-run** until explicitly applied  
- Dashboard **viewer** until `allow_control` enabled on host  
- Config files written **0600**  
- Reports are **not** a certification of clearance  

---

## 6. Cheatsheet (copy)

```
SETUP     python3 setup.py && python3 sentinel.py doctor
MONITOR   python3 sentinel.py hunt
SERVICE   python3 sentinel.py service-install
UI        python3 sentinel.py dashboard
PDF       Dashboard → Generate PDF  OR  /api/report/pdf?token=...
CANARIES  python3 sentinel.py deception
FIM       python3 sentinel.py integrity
STATUS    python3 sentinel.py doctor | status | report
STOP HUNT Ctrl+C
```

---

## 7. Support

**TrinTech Digital Defense** · Trinidad & Tobago  
WhatsApp: **+1 868 362-0679**  
Authorized defensive use only.
