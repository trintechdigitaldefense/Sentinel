# SENTINEL — Sales pack (Caribbean SMB)

**TrinTech Digital Defense** · Authorized defensive monitoring only

---

## One-line pitch

Continuous host monitoring and early warning for your server — canaries, shell detection, file integrity, SSH abuse blocking, clear alerts and reports — without a full SOC.

---

## What the pilot includes (fixed)

| Item | Included |
|------|----------|
| Install + doctor on **1 Linux host** | Yes |
| FIM + SUID + persistence baselines | Yes |
| Canary / decoy deployment | Yes |
| Continuous hunt (service or supervised) | Yes |
| Alert channel (WhatsApp **or** email **or** Splunk) | One channel |
| Pilot validation report (`pilot` + `field-soak`) | Yes |
| PDF / evidence snapshot at end of pilot | Yes |
| Duration | **14 days** |
| On-site / remote sessions | **1 install + 1 readout** |

**Not included in pilot:** multi-site fleet, 24/7 SOC, custom SIEM engineering, Windows estate, offensive testing.

---

## Fixed pilot price (recommend)

| Package | Price (guide) | Notes |
|---------|----------------|-------|
| **Pilot — Single host** | **USD 450** / **TTD 3,000** | 14-day pilot, one host |
| **Pilot + readout workshop** | **USD 650** / **TTD 4,400** | Adds 1-hour management readout |
| **Convert to monthly** | **USD 200–350** / host / month | After successful pilot |

*Adjust to your cost of travel and support. Keep pilot fixed so proposals stay simple.*

---

## Client go-live runbook (one page)

```text
1. Written authorization (scope: host IP, monitoring only)
2. git clone + python3 setup.py
3. python3 sentinel.py pilot
4. python3 sentinel.py integrity
5. python3 sentinel.py deception
6. python3 sentinel.py service-install   # or menu 1 continuous
7. python3 sentinel.py field-soak --confirm
8. Optional: siem splunk-configure  OR  WhatsApp in config
9. Hand over: dashboard URL, critical ack process, pilot_report.json
```

### During the 14 days

- Leave continuous protection running  
- Client contacts you only on **CRITICAL** (canary, shell, integrity)  
- You ACK criticals after triage: `python3 sentinel.py critical ack <id>`

### End of pilot

- Run `pilot` + `field-soak` again  
- Deliver PDF report + 30-minute readout  
- Propose monthly if detection/value was clear  

---

## Objection handlers

| Concern | Response |
|---------|----------|
| “We need a full SOC” | Pilot is early warning on the server you care about — not a SOC replacement. |
| “Will it lock us out?” | Firewall stays dry-run unless confirmed; lockout guard protects operator SSH. |
| “Is source reviewable?” | Yes — plain Python on GitHub under authorized defensive use. |

---

## Friendly-site field soak (internal)

1. Choose 1–2 trusted hosts with written OK  
2. `field-soak --confirm` (canary + sim probes)  
3. Confirm alert path (WhatsApp message or Splunk event or ship file growth)  
4. Log results in engagement folder; fix gaps before paid pilots  

See [FIELD_SOAK.md](FIELD_SOAK.md) and [PILOT.md](PILOT.md).
